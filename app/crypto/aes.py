# """AES-128(ECB)+PKCS#7 helpers (use library).""" 
# raise NotImplementedError("students: implement AES helpers")



from Crypto.Cipher import AES
import secrets
import base64

BLOCK_SIZE = 16

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def aes_encrypt_cbc_base64(key: bytes, plaintext: bytes) -> str:
    """
    Encrypt plaintext with AES-128-CBC using random IV.
    Return base64(iv || ciphertext).
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext))
    return base64.b64encode(iv + ct).decode()

def aes_decrypt_cbc_base64(key: bytes, iv_ct_b64: str) -> bytes:
    """
    Input: base64(iv||ciphertext)
    Output: plaintext bytes (unpadded)
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    raw = base64.b64decode(iv_ct_b64)
    if len(raw) < 16:
        raise ValueError("Ciphertext too short")
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)
