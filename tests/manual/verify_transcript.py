import json
import hashlib
import base64
import glob
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from app.common.utils import make_message_digest_bytes, sha256_bytes

print("=== SecureChat Non-Repudiation Offline Verifier ===")

# ----------------------------------------------------------
# 1. Locate newest server transcript and receipt
# ----------------------------------------------------------
transcripts = sorted(glob.glob("transcripts/server_*.log"))
receipts    = sorted(glob.glob("transcripts/server_receipt_*.json"))

if not transcripts:
    print("No server transcripts found!")
    exit(1)

if not receipts:
    print("No server receipts found!")
    exit(1)

transcript_path = transcripts[-1]
receipt_path    = receipts[-1]

print(f"[+] Using transcript: {transcript_path}")
print(f"[+] Using receipt:    {receipt_path}")

# ----------------------------------------------------------
# 2. Load transcript raw bytes EXACTLY as hashed originally
# ----------------------------------------------------------
with open(transcript_path, "rb") as f:
    transcript_bytes = f.read()

# Decode to process message-by-message
lines = transcript_bytes.decode().splitlines()

# ----------------------------------------------------------
# 3. Load receipt JSON
# ----------------------------------------------------------
with open(receipt_path, "r") as f:
    receipt = json.load(f)

receipt_hash_hex = receipt["transcript sha256"]

# ----------------------------------------------------------
# 4. Load certificates
# ----------------------------------------------------------
client_cert = load_pem_x509_certificate(open("certs/client.crt.pem", "rb").read())
client_pub  = client_cert.public_key()

server_cert = load_pem_x509_certificate(open("certs/server.crt.pem", "rb").read())
server_pub  = server_cert.public_key()

# ----------------------------------------------------------
# IMPORTANT:
# Server transcript logs messages RECEIVED from CLIENT
# So message signatures = CLIENT private key
# → verify using CLIENT public key
# ----------------------------------------------------------

print("\n=== Checking Message Signatures ===")
all_ok = True

for line in lines:
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 5:
        print("[!] Malformed transcript line:", line)
        continue

    seqno, ts, ct, sig_b64, peer_fp = parts

    # Re-create digest exactly like client did:
    digest_input = make_message_digest_bytes(int(seqno), int(ts), ct)
    digest = sha256_bytes(digest_input)


    sig_raw = base64.b64decode(sig_b64)

    try:
        # Client signed → verify using CLIENT public key
        client_pub.verify(
            sig_raw,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"[OK] seq {seqno} signature valid")
    except Exception as e:
        print(f"[FAIL] seq {seqno} signature INVALID!")
        all_ok = False

# ----------------------------------------------------------
# 6. Verify transcript hash EXACTLY like Transcript.generate_receipt()
# ----------------------------------------------------------
print("\n=== Checking Transcript Hash ===")

computed_hash_hex = hashlib.sha256(transcript_bytes).hexdigest()

print("Computed:", computed_hash_hex)
print("Receipt :", receipt_hash_hex)

if computed_hash_hex == receipt_hash_hex:
    print("[OK] Transcript hash matches")
else:
    print("[FAIL] Transcript hash mismatch!")
    all_ok = False

# ----------------------------------------------------------
# 7. Verify receipt signature
# Receipt was signed by the SERVER in server_receipt_*.json
# So verify with SERVER public key
# ----------------------------------------------------------
print("\n=== Checking Receipt RSA Signature ===")

try:
    server_pub.verify(
        base64.b64decode(receipt["sig"]),
        bytes.fromhex(receipt_hash_hex),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    print("[OK] Receipt signature valid")
except Exception as e:
    print("[FAIL] Receipt signature INVALID!")
    all_ok = False

# ----------------------------------------------------------
# 8. Final Verdict
# ----------------------------------------------------------
print("\n=== FINAL RESULT ===")
if all_ok:
    print("[PASS] Non-repudiation verification SUCCESS ✔")
else:
    print("[FAIL] Verification FAILED ✘")
