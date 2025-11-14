
#!/usr/bin/env python3
"""
Integrated SecureChat server (console). Plain TCP (no TLS) - application-layer crypto.

Basic behavior:
- Accept a single client connection (for assignment simplicity).
- Perform hello exchange (receive client cert, verify).
- Temporary DH to receive encrypted register/login payload and handle DB.
- Session DH to establish SESSION_KEY.
- Start message receive/send loop with transcripting and signature verification.
- On /quit or disconnect, generate SessionReceipt and save it.
"""

import socket
import json
import threading
import argparse
import time
from pathlib import Path

from app.crypto.pki import load_cert_from_file, load_cert_from_pem_string, verify_cert
from app.crypto.dh import P_2048, G, dh_generate_private, dh_public_value, dh_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt_cbc_base64, aes_decrypt_cbc_base64
from app.crypto.sign import load_private_key_pem, rsa_sign_base64, rsa_verify_base64
from app.common.utils import now_ms, b64e, b64d, make_message_digest_bytes, sha256_bytes
from app.storage.transcript import Transcript
from app.storage import db as dbmod

# Config
CA_CERT_PATH = "certs/ca.crt.pem"
SERVER_CERT_PATH = "certs/server.crt.pem"
SERVER_KEY_PATH = "certs/server.key.pem"

def send_json(sock: socket.socket, obj: dict):
    data = json.dumps(obj) + "\n"
    sock.sendall(data.encode())

def recv_json(sock: socket.socket) -> dict:
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
        if b"\n" in buf:
            line, rest = buf.split(b"\n", 1)
            return json.loads(line.decode())

def gen_nonce() -> str:
    return b64e(__import__("secrets").token_bytes(16))


class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.conn = None
        self.addr = None

        self.ca_cert = load_cert_from_file(CA_CERT_PATH)
        self.my_cert_pem = open(SERVER_CERT_PATH, "r").read()
        self.my_priv = load_private_key_pem(SERVER_KEY_PATH)
        self.peer_cert = None

        self.aes_temp_key = None
        self.session_key = None

        self.transcript = None
        self.send_seq = 1
        self.last_recv_seq = 0

        self.running = True

    def bind_and_accept(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(1)
        print(f"[*] Listening on {self.host}:{self.port}")
        conn, addr = s.accept()
        self.conn = conn
        self.addr = addr
        print("[+] Accepted connection from", addr)

    # -----------------------
    # Control plane: receive hello and verify client cert
    # -----------------------
    def handle_hello(self):
        msg = recv_json(self.conn)
        if msg.get("type") != "hello":
            raise RuntimeError("Expected hello")
        client_cert_pem = msg.get("client_cert")
        self.peer_cert = load_cert_from_pem_string(client_cert_pem)
        ok, reason = verify_cert(self.peer_cert, self.ca_cert, expected_cn="client.local")
        if not ok:
            send_json(self.conn, {"type": "BAD_CERT"})
            raise RuntimeError("Client certificate verification failed: " + reason)
        # send server_hello
        send_json(self.conn, {"type": "server_hello", "server_cert": self.my_cert_pem, "nonce": gen_nonce()})
        print("[+] Client certificate verified and server_hello sent")

    # -----------------------
    # Temporary DH -> AES_TEMP_KEY
    # -----------------------
    def handle_temp_dh(self):
        msg = recv_json(self.conn)
        if msg.get("type") != "dh_client":
            raise RuntimeError("Expected dh_client")
        A = int(msg["A"])
        b = dh_generate_private()
        B = dh_public_value(b)
        send_json(self.conn, {"type": "dh_server", "B": B})
        ks = dh_shared_secret(A, b)
        self.aes_temp_key = derive_aes_key(ks)
        print("[+] Derived AES_TEMP_KEY")

    # -----------------------
    # Handle register/login (encrypted)
    # -----------------------
    def handle_register_or_login(self):
        msg = recv_json(self.conn)
        mtype = msg.get("type")
        payload = msg.get("payload")
        try:
            pt = aes_decrypt_cbc_base64(self.aes_temp_key, payload)
            data = json.loads(pt.decode())
        except Exception as e:
            send_json(self.conn, {"status": "error", "reason": "decrypt_failed"})
            return False

        if mtype == "register":
            email = data["email"]
            username = data["username"]
            password = data["password"]
            # Registration: create salt, store salted hash
            try:
                salt = __import__("secrets").token_bytes(16)
                pwd_hash = __import__("hashlib").sha256(salt + password.encode()).hexdigest()
                dbmod.create_user(email, username, salt, pwd_hash)
                send_json(self.conn, {"status": "ok", "msg": "registered"})
                print(f"[+] Registered user {username}")
                return True
            except Exception as e:
                send_json(self.conn, {"status": "error", "reason": str(e)})
                return False

        elif mtype == "login":
            username = data["username"]
            password = data["password"]
            try:
                rec = dbmod.get_user_by_username(username)
                if rec is None:
                    send_json(self.conn, {"status": "error", "reason": "user_not_found"})
                    return False
                salt = rec["salt"]
                expected_hash = rec["pwd_hash"]
                supplied_hash = __import__("hashlib").sha256(salt + password.encode()).hexdigest()
                import hmac
                if hmac.compare_digest(supplied_hash, expected_hash):
                    send_json(self.conn, {"status": "ok", "msg": "login_success"})
                    print(f"[+] User {username} logged in")
                    return True
                else:
                    send_json(self.conn, {"status": "error", "reason": "bad_credentials"})
                    return False
            except Exception as e:
                send_json(self.conn, {"status": "error", "reason": str(e)})
                return False
        else:
            send_json(self.conn, {"status": "error", "reason": "unknown_type"})
            return False

    # -----------------------
    # Session DH -> derive SESSION_KEY
    # -----------------------
    def handle_session_dh(self):
        msg = recv_json(self.conn)
        if msg.get("type") != "session_dh_client":
            raise RuntimeError("Expected session_dh_client")
        A = int(msg["A"])
        b = dh_generate_private()
        B = dh_public_value(b)
        send_json(self.conn, {"type": "session_dh_server", "B": B})
        ks = dh_shared_secret(A, b)
        self.session_key = derive_aes_key(ks)
        print("[+] Derived SESSION_KEY")
        self.transcript = Transcript("server")

    # -----------------------
    # Receive loop
    # -----------------------
    def recv_loop(self):
        while self.running:
            try:
                msg = recv_json(self.conn)
            except ConnectionError:
                print("[!] Client closed connection")
                self.running = False
                break
            if not msg:
                continue
            mtype = msg.get("type")
            if mtype == "msg":
                seq = int(msg["seqno"])
                ts = int(msg["ts"])
                ct_b64 = msg["ct"]
                sig_b64 = msg["sig"]

                if seq <= self.last_recv_seq:
                    print("[!] REPLAY detected:", seq)
                    continue

                # timestamp check (60s)
                if abs(now_ms() - ts) > 60000:
                    print("[!] Stale message")
                    continue

                digest_input = make_message_digest_bytes(seq, ts, ct_b64)
                digest = sha256_bytes(digest_input)
                pub = self.peer_cert.public_key()
                if not rsa_verify_base64(pub, digest, sig_b64):
                    print("[!] SIG_FAIL for seq", seq)
                    continue

                try:
                    pt = aes_decrypt_cbc_base64(self.session_key, ct_b64)
                    print(f"\n[client] {pt.decode()}")
                except Exception as e:
                    print("[!] Decrypt failed:", e)
                    continue

                from cryptography.hazmat.primitives import hashes
                peer_fp = self.peer_cert.fingerprint(hashes.SHA256()).hex()

                self.transcript.append(seq, ts, ct_b64, sig_b64, peer_fp)
                self.last_recv_seq = seq

            elif mtype == "receipt":
                print("[*] Received receipt from client:", msg)

            else:
                print("[*] Received:", msg)

    # -----------------------
    # Server send message (console)
    # -----------------------
    def send_message(self, text: str):
        ts = now_ms()
        ct_b64 = aes_encrypt_cbc_base64(self.session_key, text.encode())
        digest_input = make_message_digest_bytes(self.send_seq, ts, ct_b64)
        digest = sha256_bytes(digest_input)
        sig_b64 = rsa_sign_base64(self.my_priv, digest)
        msg = {"type": "msg", "seqno": self.send_seq, "ts": ts, "ct": ct_b64, "sig": sig_b64}
        send_json(self.conn, msg)
        self.send_seq += 1


    # -----------------------
    # Helper: generate and send receipt
    # -----------------------
    def generate_and_send_receipt(self):
        try:
            receipt = self.transcript.generate_receipt(self.my_priv, "server")
            print("[*] SessionReceipt generated:", receipt)
            try:
                # try to send to client; ignore failures if connection closed
                send_json(self.conn, {"type": "receipt", **receipt})
            except Exception:
                # connection maybe closed; just save the receipt locally (already saved by generate_receipt)
                pass
        except Exception as e:
            print("[!] Failed to generate/send receipt:", e)

    # -----------------------
    # Interactive console loop
    # -----------------------
    def interactive(self):
        thr = threading.Thread(target=self.recv_loop, daemon=True)
        thr.start()

        try:
            while self.running:
                cmd = input("> ").strip()
                if not cmd:
                    continue
                if cmd == "/quit":
                    self.running = False
                    receipt = self.transcript.generate_receipt(self.my_priv, "server")
                    print("[*] SessionReceipt generated:", receipt)
                    send_json(self.conn, {"type": "receipt", **receipt})
                    break
                else:
                    self.send_message(cmd)

        except KeyboardInterrupt:
            print("\n[!] Interrupted (KeyboardInterrupt) — generating server receipt and shutting down")
            self.running = False
            # generate and (attempt to) send server receipt before exit
            try:
                # only generate if transcript exists (session may not have started)
                if self.transcript is not None:
                    self.generate_and_send_receipt()
            except Exception as e:
                print("[!] Error during shutdown receipt generation:", e)


        thr.join(timeout=1)
        try:
            self.conn.close()
        except:
            pass
        print("[*] Client handler stopped")

    # -----------------------
    # Orchestration
    # -----------------------
    def run(self):
        self.bind_and_accept()
        self.handle_hello()
        self.handle_temp_dh()
        ok = self.handle_register_or_login()
        if not ok:
            print("[!] Register/login failed; closing")
            self.conn.close()
            return

        print("[+] Auth phase completed successfully")

        # Now receive the session DH request from client
        self.handle_session_dh()
        self.interactive()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=9000)
    args = p.parse_args()

    srv = Server(args.host, args.port)
    srv.run()


if __name__ == "__main__":
    main()
