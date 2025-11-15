"""
Issue server/client certificate signed by Root CA.
Adds SAN = DNSName(CN) as required.
Generates:
    <prefix>.key.pem
    <prefix>.cert.pem
"""

import os
import argparse
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName, SubjectAlternativeName
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "certs")


def load_ca():
    """Load CA private key + CA certificate."""
    with open(os.path.join(CERTS_DIR, "ca.key.pem"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(os.path.join(CERTS_DIR, "ca.cert.pem"), "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn", required=True, help="Common Name (e.g., server.local)")
    parser.add_argument("--out", required=True, help="Output prefix (e.g., certs/server)")
    args = parser.parse_args()

    os.makedirs(CERTS_DIR, exist_ok=True)

    # Load CA for signing
    ca_key, ca_cert = load_ca()

    # Generate private key
    entity_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, args.cn),
    ])

    # Build certificate
    entity_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(entity_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            SubjectAlternativeName([DNSName(args.cn)]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Write key
    key_path = f"{args.out}.key.pem"
    with open(key_path, "wb") as f:
        f.write(
            entity_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    # Write cert
    cert_path = f"{args.out}.cert.pem"
    with open(cert_path, "wb") as f:
        f.write(entity_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] Entity key written:  {key_path}")
    print(f"[+] Entity cert written: {cert_path}")


if __name__ == "__main__":
    main()
