"""AES-128(ECB)+PKCS#7 helpers (use library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK_SIZE_BYTES = 16  # AES block size for ECB (128-bit)


def pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding to data."""
    padder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(padded: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    unpadder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-128 ECB encrypt with PKCS#7 padding.

    :param key: 16-byte AES key
    :param plaintext: raw bytes
    :return: ciphertext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    padded = pkcs7_pad(plaintext)

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128 ECB decrypt with PKCS#7 unpadding.

    :param key: 16-byte AES key
    :param ciphertext: ciphertext bytes (multiple of 16)
    :return: plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(padded)
