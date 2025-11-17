"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID, ExtensionOID


def load_cert(path: str) -> x509.Certificate:
    """Load a PEM-encoded X.509 certificate from disk."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def verify_cert_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> None:
    """
    Verify that `cert` is signed by `ca_cert`.

    Raises if the signature is invalid.
    """
    ca_public_key = ca_cert.public_key()
    ca_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


def check_validity_window(cert: x509.Certificate) -> None:
    """
    Ensure current time is within certificate validity period.

    Raises ValueError if not valid.
    """
    now = datetime.utcnow()
    if now < cert.not_valid_before or now > cert.not_valid_after:
        raise ValueError("Certificate not valid at current time")


def check_cn_or_san(cert: x509.Certificate, expected_cn: str) -> None:
    """
    Check that either SAN DNSName or subject CN matches expected_cn.

    Raises ValueError if mismatch.
    """
    # Try SAN first
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if expected_cn in dns_names:
            return
    except x509.ExtensionNotFound:
        pass

    # Fallback to CN
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("Certificate has no Common Name (CN)")
    cn = cn_attrs[0].value

    if cn != expected_cn:
        raise ValueError(f"CN mismatch: got '{cn}', expected '{expected_cn}'")


def validate_peer_cert(
    peer_cert_pem: bytes,
    ca_cert_pem: bytes,
    expected_cn: str,
) -> x509.Certificate:
    """
    High-level helper:

    1. Parse peer cert + CA cert from PEM bytes.
    2. Verify peer cert is signed by CA.
    3. Check validity window.
    4. Check CN/SAN matches expected_cn.

    Returns parsed peer certificate on success, otherwise raises.
    """
    peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    verify_cert_signed_by_ca(peer_cert, ca_cert)
    check_validity_window(peer_cert)
    check_cn_or_san(peer_cert, expected_cn)

    return peer_cert
