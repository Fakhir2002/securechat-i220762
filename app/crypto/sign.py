"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    """
    Load an unencrypted PEM-encoded RSA private key from disk.
    """
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key_from_cert(path: str):
    """
    Load public key from a PEM-encoded certificate on disk.
    """
    with open(path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert.public_key()


def rsa_sign(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign arbitrary data (usually a SHA-256 digest) using RSA PKCS#1 v1.5 + SHA-256.

    :param private_key: RSA private key
    :param data: bytes to sign (e.g., digest)
    :return: signature bytes
    """
    return private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA PKCS#1 v1.5 + SHA-256 signature.

    :param public_key: RSA public key (from cert)
    :param data: same bytes that were signed
    :param signature: signature bytes
    :return: True if valid, False otherwise
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
