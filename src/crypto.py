"""
DeadBolt — Core Cryptographic Sharding Engine
==============================================

Security Invariants (enforced here):
  1. Zero Custody: AES-256-GCM encryption/decryption is performed entirely
     client-side.  The server/db never sees the plaintext secret or the
     master key K.
  2. Shamir threshold: K is split into a 2-of-3 scheme (any 2 shards
     reconstruct K; a single shard reveals ZERO information about K).
  3. Cryptographic randomness: all nonces and keys are sourced from
     os.urandom() which is a CSPRNG on every supported platform.

Design:
  ┌──────────────────────────────────────────────────────────────────┐
  │  encrypt_secret(plaintext) ─►  (ciphertext, master_key K)       │
  │  K  ──► shamir_split(K, n=3, t=2) ─►  [S1, S2, S3]             │
  │                                                                  │
  │  Release (heir combines S1+S2 client-side):                      │
  │  shamir_combine([S1, S2]) ─►  K                                  │
  │  decrypt_secret(ciphertext, K) ─►  plaintext                    │
  └──────────────────────────────────────────────────────────────────┘

Shamir's Secret Sharing runs over GF(256) (the field used by AES),
operating byte-by-byte over the secret.  This avoids large-integer
arithmetic and handles arbitrary-length byte secrets directly.

References:
  - NIST SP 800-38D (AES-GCM)
  - Shamir, A. "How to Share a Secret." CACM 1979.
  - GF(256) polynomial reduction: x^8 + x^4 + x^3 + x + 1  (0x11b)
"""

from __future__ import annotations

import os
import secrets
import struct
from dataclasses import dataclass
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AES_KEY_BYTES: int = 32          # 256-bit master key
GCM_NONCE_BYTES: int = 12        # 96-bit nonce (NIST recommended for AES-GCM)
GCM_TAG_BYTES: int = 16          # 128-bit authentication tag (AES-GCM default)

SSS_TOTAL_SHARDS: int = 3        # n  (total shards produced)
SSS_THRESHOLD: int = 2           # t  (minimum shards required to reconstruct)

# GF(256) irreducible polynomial: x^8 + x^4 + x^3 + x + 1
_GF256_PRIME: int = 0x11B


# ---------------------------------------------------------------------------
# GF(256) Arithmetic
# ---------------------------------------------------------------------------

def _gf256_add(a: int, b: int) -> int:
    """Addition (and subtraction) in GF(256) is XOR."""
    return a ^ b


def _gf256_mul(a: int, b: int) -> int:
    """
    Multiplication in GF(256) using the Russian peasant algorithm.
    Reduction polynomial: x^8 + x^4 + x^3 + x + 1  (AES field).
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B          # low-byte of 0x11B after the implicit x^8 term
        b >>= 1
    return result


# Pre-compute multiplicative inverses for GF(256) \ {0}
_GF256_EXP: List[int] = [0] * 512
_GF256_LOG: List[int] = [0] * 256

def _build_gf256_tables() -> None:
    x = 1
    for i in range(255):
        _GF256_EXP[i] = x
        _GF256_LOG[x] = i
        x = _gf256_mul(x, 3)        # generator element 3
    for i in range(255, 512):
        _GF256_EXP[i] = _GF256_EXP[i - 255]

_build_gf256_tables()


def _gf256_div(a: int, b: int) -> int:
    """Division in GF(256): a / b via log/exp tables. b must be non-zero."""
    if b == 0:
        raise ZeroDivisionError("GF(256) division by zero")
    if a == 0:
        return 0
    return _GF256_EXP[(_GF256_LOG[a] - _GF256_LOG[b]) % 255]


# ---------------------------------------------------------------------------
# Shamir's Secret Sharing over GF(256)
# ---------------------------------------------------------------------------
#
# For each byte B of the secret K:
#   1. Sample a random degree-(t-1) polynomial f over GF(256) with f(0) = B.
#   2. Evaluate f at x = 1, 2, 3  → these are the shard byte values.
#
# Reconstruction (Lagrange interpolation):
#   Given t (x_i, y_i) pairs, recover f(0) = B.
#
# Security: a single shard y_i leaks zero information about f(0) because the
# coefficient a_1 (for t=2) is uniformly random — this is the information-
# theoretic security property of SSS.


@dataclass(frozen=True)
class Shard:
    """
    A single Shamir shard.

    Attributes:
        index:  The x-coordinate (1, 2, or 3).  MUST NOT be 0 (that is K itself).
        value:  Byte string of the same length as the original secret.
    """
    index: int      # x-coordinate in GF(256), range 1..255
    value: bytes    # one byte per secret byte


def _poly_eval_at(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial coeffs[0] + coeffs[1]*x + ... at x in GF(256)."""
    result = 0
    for c in reversed(coeffs):
        result = _gf256_add(_gf256_mul(result, x), c)
    return result


def shamir_split(secret: bytes, total: int = SSS_TOTAL_SHARDS,
                 threshold: int = SSS_THRESHOLD) -> List[Shard]:
    """
    Split *secret* into *total* shards such that any *threshold* shards
    are sufficient to reconstruct it.  A set of fewer than *threshold* shards
    reveals ZERO information about *secret*.

    Args:
        secret:    The master key bytes to protect (AES_KEY_BYTES long).
        total:     Total number of shards to produce (default 3).
        threshold: Minimum shards needed for reconstruction (default 2).

    Returns:
        A list of *total* Shard objects with indices 1..total.

    Security invariant: each polynomial's non-constant coefficients are drawn
    from os.urandom(), ensuring information-theoretic secrecy for t-1 shares.
    """
    if threshold < 2:
        raise ValueError("threshold must be >= 2")
    if total < threshold:
        raise ValueError("total must be >= threshold")
    if not secret:
        raise ValueError("secret must be non-empty")

    # shard_values[i] holds the accumulated byte string for shard index (i+1)
    shard_values: List[bytearray] = [bytearray() for _ in range(total)]

    for byte in secret:
        # Build a random degree-(threshold-1) polynomial f with f(0) = byte
        # coefficients: [f(0), a_1, a_2, ..., a_{t-1}]
        rand_coeffs = list(os.urandom(threshold - 1))
        coeffs = [byte] + rand_coeffs      # constant term = secret byte

        for i in range(total):
            x = i + 1                       # x-coordinates: 1, 2, 3, ...
            shard_values[i].append(_poly_eval_at(coeffs, x))

    return [Shard(index=i + 1, value=bytes(shard_values[i]))
            for i in range(total)]


def shamir_combine(shards: List[Shard]) -> bytes:
    """
    Reconstruct the secret from *any* 2 (or more) Shard objects via
    Lagrange interpolation over GF(256).

    Args:
        shards: A list of at least *threshold* Shard objects (order irrelevant).

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If fewer than 2 shards are provided.
    """
    if len(shards) < SSS_THRESHOLD:
        raise ValueError(
            f"At least {SSS_THRESHOLD} shards are required; got {len(shards)}"
        )

    # All shards must have the same length
    lengths = {len(s.value) for s in shards}
    if len(lengths) != 1:
        raise ValueError("Shards have inconsistent lengths — possible tampering")

    secret_len = lengths.pop()
    secret = bytearray()

    # Use only the first `threshold` shards (extras are redundant)
    active = shards[:SSS_THRESHOLD]

    for byte_idx in range(secret_len):
        # Lagrange interpolation at x=0 to recover f(0)
        result = 0
        for i, si in enumerate(active):
            xi = si.index
            yi = si.value[byte_idx]

            numerator = 1
            denominator = 1
            for j, sj in enumerate(active):
                if i == j:
                    continue
                xj = sj.index
                numerator   = _gf256_mul(numerator,   xj)           # (0 - xj) = xj in GF(256)
                denominator = _gf256_mul(denominator, _gf256_add(xi, xj))

            lagrange_coeff = _gf256_div(numerator, denominator)
            result = _gf256_add(result, _gf256_mul(yi, lagrange_coeff))

        secret.append(result)

    return bytes(secret)


# ---------------------------------------------------------------------------
# AES-256-GCM Encryption / Decryption
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EncryptedVault:
    """
    The ciphertext blob stored server-side.  Contains NO cleartext secret and
    NO master key.  The only way to recover the plaintext is to hold K.

    Layout (all fields are immutable after construction):
        nonce:       96-bit random nonce (never reused with the same key).
        ciphertext:  AES-GCM ciphertext + 128-bit authentication tag appended.
    """
    nonce: bytes        # 12 bytes
    ciphertext: bytes   # len(plaintext) + 16 bytes (GCM tag)

    def to_bytes(self) -> bytes:
        """Serialize to a compact wire/storage format: [nonce || ciphertext]."""
        return self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedVault":
        """Deserialize from the compact format produced by to_bytes()."""
        if len(data) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
            raise ValueError("Data too short to be a valid EncryptedVault blob")
        return cls(
            nonce=data[:GCM_NONCE_BYTES],
            ciphertext=data[GCM_NONCE_BYTES:],
        )


def encrypt_secret(plaintext: bytes, master_key: bytes | None = None
                   ) -> Tuple[EncryptedVault, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Args:
        plaintext:  The raw secret (seed phrase, private key, testament letter)
                    encoded as bytes.  Caller is responsible for encoding.
        master_key: Optional 32-byte key.  If None, a fresh key is generated
                    from os.urandom() — the normal production path.

    Returns:
        (EncryptedVault, master_key) — The vault blob is safe to store
        server-side; the master_key MUST be passed to shamir_split() and then
        discarded.  The caller MUST NOT persist master_key anywhere.

    Security:
        - Nonce is 12 bytes of CSPRNG randomness, never reused per key.
        - AES-GCM provides both confidentiality and integrity (via auth tag).
    """
    if master_key is None:
        master_key = os.urandom(AES_KEY_BYTES)
    if len(master_key) != AES_KEY_BYTES:
        raise ValueError(f"master_key must be exactly {AES_KEY_BYTES} bytes")

    nonce = os.urandom(GCM_NONCE_BYTES)
    aesgcm = AESGCM(master_key)
    # AESGCM.encrypt() appends the 16-byte authentication tag automatically
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return EncryptedVault(nonce=nonce, ciphertext=ciphertext), master_key


def decrypt_secret(vault: EncryptedVault, master_key: bytes) -> bytes:
    """
    Decrypt *vault* using *master_key*.

    Args:
        vault:       The EncryptedVault produced by encrypt_secret().
        master_key:  The 32-byte AES key reconstructed via shamir_combine().

    Returns:
        The original plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails (wrong key,
        corrupted ciphertext, or replay/tamper attempt).
    """
    if len(master_key) != AES_KEY_BYTES:
        raise ValueError(f"master_key must be exactly {AES_KEY_BYTES} bytes")

    aesgcm = AESGCM(master_key)
    return aesgcm.decrypt(vault.nonce, vault.ciphertext, associated_data=None)


# ---------------------------------------------------------------------------
# High-Level Vault Initialization Helper
# ---------------------------------------------------------------------------

@dataclass
class VaultBundle:
    """
    Everything produced in a single vault initialization.

    Caller responsibilities per security invariants:
        - shard_1 → store encrypted in DeadBolt State Engine DB (time-locked)
        - shard_2 → deliver to Heir immediately (dormant recovery token)
        - shard_3 → owner keeps as paper cold backup
        - master_key → MUST be zeroed / discarded after this call
        - vault → safe to store server-side (ciphertext only)
    """
    vault: EncryptedVault
    shard_1: Shard    # held by DeadBolt node — released only on DECEASED_RELEASED
    shard_2: Shard    # delivered to Heir
    shard_3: Shard    # offline cold backup


def create_vault(plaintext: bytes) -> VaultBundle:
    """
    Full vault initialization:
      1. Encrypt plaintext with a fresh AES-256-GCM key K.
      2. Split K into a 2-of-3 Shamir scheme → S1, S2, S3.
      3. Zero K in memory immediately.

    Args:
        plaintext: The secret to protect (must be non-empty bytes).

    Returns:
        A VaultBundle containing the encrypted vault and all three shards.
    """
    if not plaintext:
        raise ValueError("plaintext secret must be non-empty")

    vault, master_key = encrypt_secret(plaintext)
    shards = shamir_split(master_key)

    # Zero the master key from memory as soon as shards are created.
    # Python does not guarantee immediate memory release, but we overwrite
    # the bytearray representation as a best-effort measure.
    mk_arr = bytearray(master_key)
    for i in range(len(mk_arr)):
        mk_arr[i] = 0
    del mk_arr, master_key

    return VaultBundle(
        vault=vault,
        shard_1=shards[0],
        shard_2=shards[1],
        shard_3=shards[2],
    )
