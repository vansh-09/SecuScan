"""Vault crypto helpers using AES-GCM with key versioning.

This implementation uses PyCA `cryptography`'s AESGCM primitive and stores a
one-byte version prefix in the stored blob: [version][nonce][ciphertext+tag]

Design notes:
- `key` and `previous_keys` are expected to be base64-urlsafe encoded bytes
  (the same form returned by `Settings.resolved_vault_key`). The class will
  decode them as needed.
- `encrypt()` writes using the configured current version.
- `decrypt()` will try to use the version prefix to pick the right key, and as
  a fallback will attempt any known keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from itertools import cycle
from typing import Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _normalize_key(key: bytes) -> bytes:
    """Return raw 32-byte key for AESGCM.

    Accepts either raw 32-byte binary or urlsafe-base64 encoded bytes.
    """
    if not key:
        raise ValueError("empty vault key")
    # Only accept raw 32-byte keys for AES mode. Do NOT auto-decode base64 here
    # — the project historically stored a base64-encoded digest as the vault
    # "seed" and the legacy keystream/HMAC logic expects arbitrary bytes.
    if isinstance(key, (bytes, bytearray)) and len(key) == 32:
        return bytes(key)
    return None


class VaultCrypto:
    """AES-GCM-based vault crypto with key version awareness.

    current_version is an integer (small) that is stored as the leading byte
    in the encrypted blob.
    """

    def __init__(self, current_key: bytes, previous_keys: Optional[List[bytes]] = None, current_version: int = 2):
        # Determine whether keys are AES (32-bytes/base64) or legacy arbitrary bytes
        aes_key = _normalize_key(current_key)
        if aes_key is None:
            # legacy mode
            self.mode = "legacy"
            self.legacy_key = current_key if isinstance(current_key, (bytes, bytearray)) else str(current_key).encode("utf-8")
            self.current_key = None
        else:
            self.mode = "aes"
            self.current_key = aes_key

        self.version = int(current_version)

        # previous keys: separate lists for legacy and aes keys
        self.previous_legacy_keys: List[bytes] = []
        self.previous_aes_keys: List[bytes] = []
        for k in (previous_keys or []):
            ak = _normalize_key(k)
            if ak is None:
                self.previous_legacy_keys.append(k if isinstance(k, (bytes, bytearray)) else str(k).encode("utf-8"))
            else:
                self.previous_aes_keys.append(ak)

        # For AES mode, build a version->key map
        if self.mode == "aes":
            self._version_key_map = {}
            v = self.version
            self._version_key_map[v] = self.current_key
            for i, k in enumerate(self.previous_aes_keys, start=1):
                self._version_key_map[self.version - i] = k

    def encrypt(self, plaintext: str) -> str:
        if self.mode == "legacy":
            # original deterministic keystream + HMAC design
            raw = plaintext.encode("utf-8")
            nonce = os.urandom(16)
            stream_key = hashlib.sha256(self.legacy_key + nonce).digest()
            ciphertext = bytes(b ^ k for b, k in zip(raw, cycle(stream_key)))
            signature = hmac.new(self.legacy_key, nonce + ciphertext, hashlib.sha256).digest()
            blob = nonce + signature + ciphertext
            return base64.urlsafe_b64encode(blob).decode("ascii")

        aes = AESGCM(self.current_key)
        nonce = os.urandom(12)
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        blob = bytes([self.version]) + nonce + ct
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt(self, payload: str) -> str:
        blob = base64.urlsafe_b64decode(payload.encode("ascii"))

        # Attempt legacy format detection: nonce (16) + signature (32) + ciphertext
        if len(blob) >= 48:
            # legacy attempt using legacy key(s)
            nonce = blob[:16]
            signature = blob[16:48]
            ciphertext = blob[48:]

            # Try legacy current key
            try_keys = []
            if self.mode == "legacy":
                try_keys.append(self.legacy_key)
            try_keys.extend(self.previous_legacy_keys)

            for k in try_keys:
                expected = hmac.new(k, nonce + ciphertext, hashlib.sha256).digest()
                if hmac.compare_digest(signature, expected):
                    # successful integrity check -> decrypt stream
                    stream_key = hashlib.sha256(k + nonce).digest()
                    raw = bytes(b ^ v for b, v in zip(ciphertext, cycle(stream_key)))
                    return raw.decode("utf-8")

            # If signature fails for legacy keys, raise integrity error
            # to match previous behavior rather than falling through silently.
            raise ValueError("Vault payload integrity verification failed")

        # Otherwise, attempt AES format: [version(1)][nonce(12)][ciphertext+tag]
        if len(blob) < 1 + 12 + 16:
            raise ValueError("vault payload too short")

        version = blob[0]
        nonce = blob[1:13]
        ct = blob[13:]

        # First, try version-specific key if available
        if self.mode == "aes":
            key = self._version_key_map.get(version)
            tried = []
            if key:
                tried.append(key)
                try:
                    aes = AESGCM(key)
                    raw = aes.decrypt(nonce, ct, None)
                    return raw.decode("utf-8")
                except Exception:
                    pass

            # Fallback: try all known aes keys
            for k in [self.current_key] + self.previous_aes_keys:
                if k in tried or k is None:
                    continue
                try:
                    aes = AESGCM(k)
                    raw = aes.decrypt(nonce, ct, None)
                    return raw.decode("utf-8")
                except Exception:
                    continue

        raise ValueError("unable to decrypt vault payload with known keys")

