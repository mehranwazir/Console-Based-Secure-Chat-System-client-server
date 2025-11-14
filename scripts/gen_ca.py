"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
#raise NotImplementedError("students: implement CA generation")

#!/usr/bin/env python3
"""
scripts/gen_ca.py
Generate a root CA private key and a self-signed X.509 certificate.

Usage:
    python scripts/gen_ca.py --name "FAST-NU Root CA" --out certs/ca

This will create:
    certs/ca.key.pem   (private key, PEM, 2048-bit RSA)  - KEEP SECRET
    certs/ca.crt.pem   (self-signed certificate, PEM)
"""
import argparse
from datetime import datetime, timedelta, UTC
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def gen_ca(name: str, out_prefix: Path, days_valid: int = 3650, key_size: int = 2048):
    out_prefix.parent.mkdir(parents=True, exist_ok=True)
    key_path = out_prefix.with_suffix('.key.pem')
    cert_path = out_prefix.with_suffix('.crt.pem')

    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    # Build subject / issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days_valid))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,  # ✅ Required for CA
                key_agreement=False,
                content_commitment=True,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write private key (PEM) — keep secure!
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write certificate (PEM)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✅ Generated CA key: {key_path}")
    print(f"✅ Generated CA cert: {cert_path}")


def main():
    p = argparse.ArgumentParser(description="Generate Root CA (self-signed)")
    p.add_argument('--name', required=True, help="Common Name for the Root CA (e.g. 'FAST-NU Root CA')")
    p.add_argument('--out', default="certs/ca", help="Output prefix (default: certs/ca -> certs/ca.key.pem and certs/ca.crt.pem)")
    p.add_argument('--days', type=int, default=3650, help="Days the CA is valid (default 10 years)")
    p.add_argument('--keysize', type=int, default=2048, help="RSA key size (2048 or 4096).")
    args = p.parse_args()

    gen_ca(args.name, Path(args.out), days_valid=args.days, key_size=args.keysize)


if __name__ == "__main__":
    main()
