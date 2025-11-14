"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 
#raise NotImplementedError("students: implement PKI checks")



"""
app/crypto/pki.py

X.509 Certificate loading and verification utilities.

This module is used during the Control Plane (Negotiation & Authentication) to:
    - Load peer certificates
    - Validate certificate chain against our Root CA
    - Check CN (Common Name) identity
    - Ensure certificate is within validity period

Do NOT use TLS/SSL wrappers. Validation happens at application layer.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime
from pathlib import Path


# ----------------------------------------------------------
# Loading Certificates
# ----------------------------------------------------------

def load_cert_from_file(path: str) -> x509.Certificate:
    """
    Load a PEM-encoded certificate from disk.
    """
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


def load_cert_from_pem_string(pem_str: str) -> x509.Certificate:
    """
    Load a PEM-encoded certificate from a raw string (sent over control plane).
    """
    return x509.load_pem_x509_certificate(pem_str.encode())


# ----------------------------------------------------------
# Verification Helpers
# ----------------------------------------------------------

def get_cn(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    """
    try:
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return None


def verify_cert_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that:
        - cert.issuer == ca_cert.subject
        - cert signature is valid under CA public key
    """
    # Check issuer name
    if cert.issuer != ca_cert.subject:
        return False

    ca_public_key = ca_cert.public_key()

    try:
        # Verify signature using CA's public key
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def verify_cert_validity(cert: x509.Certificate) -> bool:
    """
    Ensure certificate is within its validity period.
    """
    now = datetime.utcnow()
    return cert.not_valid_before <= now <= cert.not_valid_after


# ----------------------------------------------------------
# Main verification function
# ----------------------------------------------------------

def verify_cert(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str,
) -> (bool, str):
    """
    Fully verify:
        - Certificate signed by our CA
        - Validity dates
        - CN matches expected_cn

    Returns:
        (True, "OK") if valid
        (False, "reason") otherwise
    """

    # Check signature
    if not verify_cert_signature(cert, ca_cert):
        return False, "invalid_signature"

    # Check validity
    if not verify_cert_validity(cert):
        return False, "expired_or_not_yet_valid"

    # Check CN
    cn = get_cn(cert)
    if cn != expected_cn:
        return False, f"cn_mismatch (expected {expected_cn}, got {cn})"

    return True, "OK"


# ----------------------------------------------------------
# Public key extraction
# ----------------------------------------------------------

def get_public_key(cert: x509.Certificate):
    """
    Return the public key object (used for RSA signature verification in data plane).
    """
    return cert.public_key()

