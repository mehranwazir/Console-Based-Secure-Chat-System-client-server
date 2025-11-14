# """RSA PKCS#1 v1.5 SHA-256 sign/verify.""" 
# raise NotImplementedError("students: implement RSA helpers")


# app/crypto/sign.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

def load_private_key_pem(path_or_pem: str):
    """
    Accept a path to a PEM file or a PEM string (detects by newline).
    Returns private key object.
    """
    from pathlib import Path
    if Path(path_or_pem).exists():
        data = Path(path_or_pem).read_bytes()
    else:
        data = path_or_pem.encode()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key_from_cert(cert):
    """
    cert: cryptography.x509.Certificate object
    Return public key object suitable for verify.
    """
    return cert.public_key()

def rsa_sign_base64(private_key, data: bytes) -> str:
    """
    Sign data with RSA PKCS1v15 + SHA256. Return base64 signature string.
    """
    sig = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()

def rsa_verify_base64(public_key, data: bytes, sig_b64: str) -> bool:
    """
    Verify signature (base64). Returns True if valid, False if not.
    """
    try:
        sig = base64.b64decode(sig_b64)
        public_key.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
