"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
from hashlib import sha256

# For simplicity, you can hard-code (p, g) or send them in protocol messages.
# These helpers are generic and work with any p, g provided by the caller.


def generate_private(p: int) -> int:
    """
    Generate a random private exponent in [2, p-2].

    :param p: prime modulus
    :return: private exponent
    """
    # 32 random bytes -> big int -> reduced mod (p-2) to fit range
    return int.from_bytes(os.urandom(32), "big") % (p - 2) + 2


def compute_public(g: int, p: int, private: int) -> int:
    """
    Compute public value A = g^a mod p.

    :param g: generator
    :param p: prime modulus
    :param private: private exponent a
    :return: public value A
    """
    return pow(g, private, p)


def compute_shared(peer_public: int, p: int, private: int) -> int:
    """
    Compute shared secret Ks = (peer_public)^a mod p.

    :param peer_public: other side's public value
    :param p: prime modulus
    :param private: our private exponent
    :return: Ks as integer
    """
    return pow(peer_public, private, p)


def derive_aes_key_from_shared(shared_int: int) -> bytes:
    """
    Derive AES-128 key from shared DH integer:

        K = Trunc16(SHA256(big-endian(Ks)))

    :param shared_int: Ks = g^(ab) mod p
    :return: 16-byte AES key
    """
    if shared_int <= 0:
        raise ValueError("Shared secret must be positive integer")

    # Convert integer to big-endian bytes
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    digest = sha256(shared_bytes).digest()
    return digest[:16]  # 16 bytes = 128 bits
