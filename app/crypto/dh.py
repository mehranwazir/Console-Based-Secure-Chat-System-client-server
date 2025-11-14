# """Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 
# raise NotImplementedError("students: implement DH helpers")


P_2048 = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A63A36210000000000090563
""".replace("\n", ""), 16)

G = 2


"""
Classic Diffie–Hellman utilities for SecureChat.
Used twice:
    - Temporary DH (for encrypted registration/login)
    - Session DH (after login, for chat AES key)
"""

import secrets
from hashlib import sha256

# ---------------------------
# DH parameters (RFC3526)
# ---------------------------
P_2048 = int("""
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A63A36210000000000090563
""".replace("\n", ""), 16)

G = 2


# ----------------------------------
# 1. Generate private exponent "a"
# ----------------------------------
def dh_generate_private():
    # random value 256 bits is enough
    return secrets.randbits(256)


# ----------------------------------
# 2. Compute public value A = g^a mod p
# ----------------------------------
def dh_public_value(a: int):
    return pow(G, a, P_2048)


# ----------------------------------
# 3. Compute shared secret Ks = B^a mod p
# ----------------------------------
def dh_shared_secret(B: int, a: int):
    return pow(B, a, P_2048)


# ----------------------------------
# 4. Convert Ks → AES key (128-bit)
# ----------------------------------
def derive_aes_key(shared_int: int):
    # Convert big int → big endian bytes
    ks_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")

    # Hash and truncate to 16 bytes
    return sha256(ks_bytes).digest()[:16]


