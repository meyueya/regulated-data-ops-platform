"""Application-layer authenticated encryption for regulated metadata."""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True, slots=True)
class FieldCipher:
    """AES-256-GCM envelope with random 96-bit nonces and explicit AAD."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("encryption key must decode to exactly 32 bytes")

    @classmethod
    def from_base64(cls, encoded: str) -> "FieldCipher":
        try:
            key = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("encryption key must be valid URL-safe base64") from exc
        return cls(key)

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.key).hexdigest()[:16]

    def encrypt(self, plaintext: str, *, associated_data: str) -> str:
        nonce = os.urandom(12)
        ciphertext = AESGCM(self.key).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            associated_data.encode("utf-8"),
        )
        envelope = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        return f"aesgcm:v1:{self.key_id}:{envelope}"

    def decrypt(self, envelope: str, *, associated_data: str) -> str:
        parts = envelope.split(":", 3)
        if len(parts) != 4 or parts[:2] != ["aesgcm", "v1"]:
            raise ValueError("unsupported ciphertext envelope")
        if parts[2] != self.key_id:
            raise ValueError("ciphertext key identifier does not match active key")
        try:
            payload = base64.b64decode(parts[3], altchars=b"-_", validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid ciphertext encoding") from exc
        if len(payload) < 28:
            raise ValueError("ciphertext envelope is truncated")
        try:
            plaintext = AESGCM(self.key).decrypt(
                payload[:12],
                payload[12:],
                associated_data.encode("utf-8"),
            )
        except InvalidTag as exc:
            raise ValueError("ciphertext authentication failed") from exc
        return plaintext.decode("utf-8")
