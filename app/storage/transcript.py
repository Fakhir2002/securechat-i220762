"""
Append-only transcript + transcript hash + receipt helpers.

Each log line:
    seqno | ts | ct_b64 | sig_b64 | peer_fpr_hex
"""

import os
import argparse
import sys
from datetime import datetime
from hashlib import sha256
from typing import Optional, Dict, Any

from app.common.utils import sha256_hex
from app.crypto.sign import rsa_sign, load_private_key


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRANSCRIPTS_DIR = os.path.join(BASE_DIR, "transcripts")
os.makedirs(TRANSCRIPTS_DIR, exist_ok=True)


class Transcript:
    """
    Handles one session's transcript file.
    """

    def __init__(self, path: str):
        self.path = path

    @classmethod
    def new(cls, prefix: str = "session") -> "Transcript":
        """
        Create a new transcript file path with timestamp.
        """
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{ts}.log"
        full_path = os.path.join(TRANSCRIPTS_DIR, filename)
        return cls(full_path)

    def append(
        self,
        seqno: int,
        ts_ms: int,
        ct_b64: str,
        sig_b64: str,
        peer_fpr_hex: str,
    ) -> None:
        """
        Append a single line to the transcript.
        """
        line = f"{seqno}|{ts_ms}|{ct_b64}|{sig_b64}|{peer_fpr_hex}\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)

    def compute_hash(self) -> str:
        """
        Compute SHA-256 over the concatenation of all lines.
        Returns hex digest.
        """
        if not os.path.exists(self.path):
            raise FileNotFoundError(self.path)

        h = sha256()
        with open(self.path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()

    def load_lines(self):
        """
        Return list of raw lines (str).
        """
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as f:
            return [line.rstrip("\n") for line in f]


def fingerprint_cert_der(der_bytes: bytes) -> str:
    """
    Helper to compute SHA-256 fingerprint of a certificate (DER).
    """
    return sha256_hex(der_bytes)


def make_session_receipt(
    transcript: Transcript,
    peer_role: str,
    first_seq: int,
    last_seq: int,
    priv_key_path: str,
) -> Dict[str, Any]:
    """
    Build a SessionReceipt dict as described in the assignment:

        {
          "type": "receipt",
          "peer": "client" | "server",
          "first_seq": ...,
          "last_seq": ...,
          "transcript_sha256": "...",
          "sig": base64(signature)
        }

    Signature is over the transcript_sha256 (hex string as bytes).
    """
    from app.common.utils import b64_encode  # local import to avoid cycles

    transcript_hash = transcript.compute_hash()
    private_key = load_private_key(priv_key_path)
    sig_bytes = rsa_sign(private_key, transcript_hash.encode("ascii"))
    sig_b64 = b64_encode(sig_bytes)

    receipt = {
        "type": "receipt",
        "peer": peer_role,
        "first_seq": first_seq,
        "last_seq": last_seq,
        "transcript_sha256": transcript_hash,
        "sig": sig_b64,
    }
    return receipt


def _cli_verify(path: str) -> None:
    """
    Offline verify helper stub – here we just print the hash.
    You can extend this to also verify the receipt signature.
    """
    t = Transcript(path)
    h = t.compute_hash()
    print(f"[Transcript] {path}")
    print(f"[Transcript] SHA-256: {h}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--verify",
        metavar="PATH",
        help="Compute and print transcript hash for given file",
    )
    args = parser.parse_args(argv)

    if args.verify:
        _cli_verify(args.verify)
    else:
        parser.print_help()


if __name__ == "__main__":
    main(sys.argv[1:])
