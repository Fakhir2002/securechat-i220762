"""
Create Root CA (RSA + self-signed X.509) using cryptography.
Generates:
    certs/ca.key.pem   (private key, NOT to be committed)
    certs/ca.cert.pem  (self-signed root certificate)
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "certs")


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)

    # 1. Generate CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Define CA subject/issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])

    # 3. Build self-signed certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # self-signed
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=1))
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # 4. Write private key
    key_path = os.path.join(CERTS_DIR, "ca.key.pem")
    with open(key_path, "wb") as f:
        f.write(
            ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    # 5. Write certificate
    cert_path = os.path.join(CERTS_DIR, "ca.cert.pem")
    with open(cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] CA private key written to: {key_path}")
    print(f"[+] CA certificate   written to: {cert_path}")
    print("[!] DO NOT COMMIT ca.key.pem TO GITHUB")


if __name__ == "__main__":
    main()
