# tests/test_dataplane.py
import time
from app.crypto.aes import aes_encrypt_cbc_base64, aes_decrypt_cbc_base64
from app.crypto.sign import rsa_sign_base64, rsa_verify_base64, load_private_key_pem
from app.common.utils import make_message_digest_bytes, sha256_bytes
from app.crypto.pki import load_cert_from_file

# Load keys & certs (you should have generated these earlier)
PRIVPATH = "certs/client.key.pem"   # use a private key you generated
CERTPATH = "certs/client.crt.pem"

# Load private key (cryptography)
priv = load_private_key_pem(PRIVPATH)

# Load cert to extract public key to verify
cert = load_cert_from_file(CERTPATH)
pub = cert.public_key()

# Shared AES key (simulate derived session key)
# For test use 16 bytes from repeated pattern or derive using dh test earlier
AES_KEY = b"0123456789ABCDEF"  # << only for test; replace with derived key in real app

# Compose a plaintext message
plaintext = b"Hello server, this is a secret message."

# Encrypt
ct_b64 = aes_encrypt_cbc_base64(AES_KEY, plaintext)
print("Ciphertext (b64):", ct_b64)

# Create seqno and timestamp
seqno = 1
ts_ms = int(time.time() * 1000)

# Build digest bytes and sign
digest_input = make_message_digest_bytes(seqno, ts_ms, ct_b64)
digest = sha256_bytes(digest_input)

sig_b64 = rsa_sign_base64(priv, digest)
print("Signature (b64):", sig_b64)

# Now verify signature (receiver side)
ok = rsa_verify_base64(pub, digest, sig_b64)
print("Signature valid:", ok)

# Decrypt ciphertext and compare
decrypted = aes_decrypt_cbc_base64(AES_KEY, ct_b64)
print("Decrypted:", decrypted)
print("Plaintext match:", decrypted == plaintext)
