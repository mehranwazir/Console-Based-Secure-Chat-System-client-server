# """Append-only transcript + TranscriptHash helpers.""" 
# raise NotImplementedError("students: implement transcript layer")


"""
Append-only transcript storage + transcript hashing + SessionReceipt generation.

Transcript line format:
    seqno | ts | ct | sig | peer_fingerprint

SessionReceipt JSON format:
{
    "type": "receipt",
    "peer": "client" | "server",
    "first seq": ...,
    "last seq": ...,
    "transcript sha256": "...hex...",
    "sig": "...base64..."
}

This module ensures non-repudiation as required by the assignment.
"""

import json
from pathlib import Path
from hashlib import sha256
from datetime import datetime

from app.common.utils import sha256_hex
from app.crypto.sign import rsa_sign_base64


class Transcript:
    def __init__(self, role: str):
        """
        role: "client" or "server"
        Creates a new transcript file with a timestamped filename.
        """
        assert role in ("client", "server")

        self.role = role
        self.start_time = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        Path("transcripts").mkdir(exist_ok=True)

        self.filepath = Path(f"transcripts/{role}_{self.start_time}.log")

        # Initialize file
        self.filepath.touch()

        self.first_seq = None
        self.last_seq = None

    # ----------------------------------------------------------
    # Append new message line
    # ----------------------------------------------------------
    def append(self, seqno: int, ts_ms: int, ct_b64: str, sig_b64: str, peer_fp: str):
        """
        Append a message entry to the transcript.
        seqno | ts | ct | sig | peer_fingerprint
        """

        if self.first_seq is None:
            self.first_seq = seqno
        self.last_seq = seqno

        line = f"{seqno} | {ts_ms} | {ct_b64} | {sig_b64} | {peer_fp}\n"

        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(line)

    # ----------------------------------------------------------
    # Compute transcript hash
    # ----------------------------------------------------------
    def compute_transcript_hash(self) -> str:
        """
        Read transcript file as raw bytes and compute SHA256 hex digest.
        This ensures ANY modification to transcript invalidates the hash.
        """
        content = self.filepath.read_bytes()
        return sha256_hex(content)

    # ----------------------------------------------------------
    # Generate SessionReceipt
    # ----------------------------------------------------------
    def generate_receipt(self, private_key, peer: str) -> dict:
        """
        private_key: cryptography RSA private key object
        peer: "client" or "server" (which peer this receipt describes)
        Returns dict of SessionReceipt.
        """

        thash = self.compute_transcript_hash()             # hex string
        thash_bytes = bytes.fromhex(thash)                 # convert to raw bytes for signing

        sig_b64 = rsa_sign_base64(private_key, thash_bytes)

        receipt = {
            "type": "receipt",
            "peer": peer,
            "first seq": self.first_seq,
            "last seq": self.last_seq,
            "transcript sha256": thash,
            "sig": sig_b64,
        }

        # Save receipt to file
        out_path = Path(f"transcripts/{peer}_receipt_{self.start_time}.json")
        out_path.write_text(json.dumps(receipt, indent=2))

        return receipt
