
#!/usr/bin/env python3
"""
Integrated SecureChat client (console). Plain TCP (no TLS) - application-layer crypto.

Flow:
1. connect -> hello (send client cert + nonce)
2. receive server_hello -> verify cert
3. ephemeral DH -> AES_TEMP_KEY
4. encrypted register/login using AES_TEMP_KEY
5. session DH -> SESSION_KEY
6. chat loop (send/receive signed+encrypted messages)
7. on /quit -> generate and save SessionReceipt
"""

import cmd
import socket
import json
import threading
import argparse
import sys
import time
import base64
from os import path

from app.crypto.pki import load_cert_from_file, load_cert_from_pem_string, verify_cert
from app.crypto.dh import P_2048, G, dh_generate_private, dh_public_value, dh_shared_secret, derive_aes_key
from app.crypto.aes import aes_encrypt_cbc_base64, aes_decrypt_cbc_base64
from app.crypto.sign import load_private_key_pem, rsa_sign_base64, rsa_verify_base64
from app.common.utils import now_ms, b64e, b64d, make_message_digest_bytes, sha256_bytes
from app.storage.transcript import Transcript
# DB functions (registration/login)
from app.storage import db as dbmod

# Config
CA_CERT_PATH = "certs/ca.crt.pem"
CLIENT_CERT_PATH = "certs/client.crt.pem"
CLIENT_KEY_PATH = "certs/client.key.pem"

# Message helpers (line-delimited JSON)
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
            # keep rest in socket buffer by leaving it (simple; not a full streaming parser)
            return json.loads(line.decode())

def gen_nonce() -> str:
    return b64e(__import__("secrets").token_bytes(16))


class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None

        # certs & keys
        self.ca_cert = load_cert_from_file(CA_CERT_PATH)
        self.my_cert_pem = open(CLIENT_CERT_PATH, "r").read()
        self.my_priv = load_private_key_pem(CLIENT_KEY_PATH)
        self.peer_cert = None

        # crypto keys
        self.aes_temp_key = None
        self.session_key = None

        # transcript & seqno
        self.transcript = None
        self.send_seq = 1
        self.last_recv_seq = 0

        # runtime
        self.running = True

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))
        self.sock = s
        print(f"[+] Connected to {self.host}:{self.port}")

    # -----------------------
    # Control plane: hello
    # -----------------------
    def do_hello_exchange(self):
        nonce = gen_nonce()
        hello = {"type": "hello", "client_cert": self.my_cert_pem, "nonce": nonce}
        send_json(self.sock, hello)
        print("[*] Sent hello")

        resp = recv_json(self.sock)
        if resp.get("type") == "BAD_CERT":
            raise RuntimeError("Server rejected our certificate: BAD_CERT")

        if resp.get("type") != "server_hello":
            raise RuntimeError("Unexpected message during hello exchange")

        server_cert_pem = resp.get("server_cert")
        self.peer_cert = load_cert_from_pem_string(server_cert_pem)

        ok, reason = verify_cert(self.peer_cert, self.ca_cert, expected_cn="server.local")
        if not ok:
            raise RuntimeError(f"Server certificate verification failed: {reason}")

        print("[+] Server certificate verified OK")

    # -----------------------
    # Temporary DH -> AES_TEMP_KEY
    # -----------------------
    def do_temp_dh(self):
        a = dh_generate_private()
        A = dh_public_value(a)
        send_json(self.sock, {"type": "dh_client", "p": P_2048, "g": G, "A": A})
        resp = recv_json(self.sock)
        if resp.get("type") != "dh_server":
            raise RuntimeError("Expected dh_server response")
        B = int(resp["B"])
        ks = dh_shared_secret(B, a)
        self.aes_temp_key = derive_aes_key(ks)
        print("[+] Derived AES_TEMP_KEY")

    # -----------------------
    # Registration / Login (encrypted under AES_TEMP_KEY)
    # -----------------------
    def register_flow(self):
        print("=== Registration ===")
        email = input("email: ").strip()
        username = input("username: ").strip()
        password = input("password: ").strip()

        payload = {"email": email, "username": username, "password": password}
        pt = json.dumps(payload).encode()
        ct_b64 = aes_encrypt_cbc_base64(self.aes_temp_key, pt)
        send_json(self.sock, {"type": "register", "payload": ct_b64})
        print("[*] Sent encrypted registration payload")
        resp = recv_json(self.sock)
        print("Server:", resp)

    def login_flow(self):
        print("=== Login ===")
        username = input("username: ").strip()
        password = input("password: ").strip()
        payload = {"username": username, "password": password}
        pt = json.dumps(payload).encode()
        ct_b64 = aes_encrypt_cbc_base64(self.aes_temp_key, pt)
        send_json(self.sock, {"type": "login", "payload": ct_b64})
        print("[*] Sent encrypted login payload")
        resp = recv_json(self.sock)
        print("Server:", resp)
        if resp.get("status") == "ok":
            return True
        return False

    # -----------------------
    # Session DH (derive SESSION_KEY)
    # -----------------------
    def do_session_dh(self):
        a = dh_generate_private()
        A = dh_public_value(a)
        send_json(self.sock, {"type": "session_dh_client", "p": P_2048, "g": G, "A": A})
        resp = recv_json(self.sock)
        if resp.get("type") != "session_dh_server":
            raise RuntimeError("Expected session_dh_server")
        B = int(resp["B"])
        ks = dh_shared_secret(B, a)
        self.session_key = derive_aes_key(ks)
        print("[+] Derived SESSION_KEY")
        # create transcript now
        self.transcript = Transcript("client")

    # -----------------------
    # Data plane: send message
    # -----------------------
    def send_message(self, plaintext: str):
        ts = now_ms()
        ct_b64 = aes_encrypt_cbc_base64(self.session_key, plaintext.encode())
        digest_input = make_message_digest_bytes(self.send_seq, ts, ct_b64)
        digest = sha256_bytes(digest_input)
        sig_b64 = rsa_sign_base64(self.my_priv, digest)
        msg = {
            "type": "msg",
            "seqno": self.send_seq,
            "ts": ts,
            "ct": ct_b64,
            "sig": sig_b64
        }

        # --- Tamper Test: flip one byte if plaintext == "attack" ---
        if plaintext.strip() == "attack":
            print("[*] TAMPERING: Flipping 1 byte in ciphertext for SIG_FAIL test!")
            # Convert ct_b64 to mutable bytearray
            corrupt = bytearray(msg["ct"].encode())
            # Flip 1 bit of a byte in the Base64 string (safe because server will reject it anyway)
            corrupt[-2] ^= 1       # XOR flip
            msg["ct"] = corrupt.decode()


        send_json(self.sock, msg)
        self.last_sent = msg.copy()   # save last message
       
        # self.transcript.append(self.send_seq, ts, ct_b64, sig_b64, self.peer_cert.fingerprint(...).hex())
        self.send_seq += 1

    # -----------------------
    # Data plane: receive loop
    # -----------------------
    def recv_loop(self):
        while self.running:
            try:
                msg = recv_json(self.sock)
            except ConnectionError:
                print("[!] Connection closed by server")
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

                # Replay check
                if seq <= self.last_recv_seq:
                    print("[!] REPLAY detected:", seq)
                    continue

                # Timestamp freshness (60s window)
                now = now_ms()
                if abs(now - ts) > 60000:
                    print("[!] Stale message (timestamp outside allowed window)")
                    continue

                # Verify signature
                digest_input = make_message_digest_bytes(seq, ts, ct_b64)
                digest = sha256_bytes(digest_input)
                pub = self.peer_cert.public_key()
                if not rsa_verify_base64(pub, digest, sig_b64):
                    print("[!] SIG_FAIL for seq", seq)
                    continue

                # Decrypt
                try:
                    pt = aes_decrypt_cbc_base64(self.session_key, ct_b64)
                    print(f"\n[peer] {pt.decode()}")
                except Exception as e:
                    print("[!] Decryption/Padding failed:", e)
                    continue

                # Append to transcript
                from cryptography.hazmat.primitives import hashes
                peer_fp = self.peer_cert.fingerprint(hashes.SHA256()).hex()
                self.transcript.append(seq, ts, ct_b64, sig_b64, peer_fp)
                self.last_recv_seq = seq

            elif mtype == "receipt":
                print("[*] Received session receipt from server:", msg)

            else:
                print("[*] Received:", msg)

    # -----------------------
    # Main interactive loop
    # -----------------------
    def interactive(self):
        # Start receiver thread
        thr = threading.Thread(target=self.recv_loop, daemon=True)
        thr.start()

        try:
            while self.running:
                cmd = input("> ").strip()

                if cmd == "/replay":
                    print("[*] Replaying last message...")
                    if self.last_sent is not None:
                        send_json(self.sock, self.last_sent)
                    else:
                        print("[!] No previous message to replay.")
                    continue

                if not cmd:
                    continue
                if cmd == "/quit":
                    self.running = False
                    # generate receipt and save
                    receipt = self.transcript.generate_receipt(self.my_priv, "client")
                    print("[*] SessionReceipt generated:", receipt)
                    # optionally send to server
                    send_json(self.sock, {"type": "receipt", **receipt})
                    break
                else:
                    self.send_message(cmd)
        except KeyboardInterrupt:
            print("\n[!] Interrupted")
            self.running = False

        thr.join(timeout=1)
        self.sock.close()
        print("[*] Disconnected")

    # -----------------------
    # Orchestration
    # -----------------------
    def run(self):
        self.connect()
        self.do_hello_exchange()
        self.do_temp_dh()

        # choose register or login
        choice = input("Do you want to (r)egister or (l)ogin? [r/l]: ").strip().lower()
        if choice == "r":
            self.register_flow()
            # After registration, require login
            print("[*] Now login")
            ok = self.login_flow()
            if not ok:
                print("[!] Login failed")
                return
        else:
            ok = self.login_flow()
            if not ok:
                print("[!] Login failed")
                return

        # session DH and chat
        self.do_session_dh()
        self.interactive()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    args = p.parse_args()

    client = Client(args.host, args.port)
    client.run()


if __name__ == "__main__":
    main()
