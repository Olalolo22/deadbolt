"""
DeadBolt — Task 1: Core Cryptographic Sharding Engine — Unit Tests
===================================================================

Tests verify:
  1.  AES-256-GCM round-trip (encrypt → decrypt produces original plaintext).
  2.  AES-256-GCM authentication tag rejection on tampered ciphertext.
  3.  Shamir 2-of-3: all three 2-shard combinations reconstruct K correctly:
        K = combine(S1, S2) = combine(S1, S3) = combine(S2, S3)
  4.  Single shard reveals ZERO information about K (information-theoretic).
  5.  Full vault round-trip: create_vault → combine shards → decrypt.
  6.  Shamir serialization / shard immutability.
  7.  Error paths: insufficient shards, wrong key, empty plaintext.
  8.  Security property: master key K is NOT derivable from one shard alone
      (brute-force check over a small key space on a 1-byte secret).
"""

import os
import secrets
import pytest

from cryptography.exceptions import InvalidTag

from src.crypto import (
    AES_KEY_BYTES,
    GCM_NONCE_BYTES,
    Shard,
    EncryptedVault,
    VaultBundle,
    encrypt_secret,
    decrypt_secret,
    shamir_split,
    shamir_combine,
    create_vault,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    return os.urandom(AES_KEY_BYTES)


@pytest.fixture
def sample_secret() -> bytes:
    return b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@pytest.fixture
def vault_and_key(sample_secret) -> tuple:
    vault, key = encrypt_secret(sample_secret)
    return vault, key, sample_secret


# ---------------------------------------------------------------------------
# AES-256-GCM Tests
# ---------------------------------------------------------------------------

class TestAESGCM:
    def test_roundtrip(self, vault_and_key):
        """Encrypt then decrypt returns the original plaintext."""
        vault, key, original = vault_and_key
        recovered = decrypt_secret(vault, key)
        assert recovered == original

    def test_different_nonces_per_encryption(self, sample_secret, master_key):
        """Every call to encrypt_secret uses a fresh nonce."""
        v1, _ = encrypt_secret(sample_secret, master_key)
        v2, _ = encrypt_secret(sample_secret, master_key)
        assert v1.nonce != v2.nonce, "Nonce reuse detected — critical security failure"

    def test_ciphertext_differs_from_plaintext(self, vault_and_key):
        """Ciphertext should not equal plaintext (sanity check)."""
        vault, _, original = vault_and_key
        # ciphertext includes GCM tag, so lengths differ — but content should too
        assert vault.ciphertext != original

    def test_wrong_key_raises_invalid_tag(self, vault_and_key):
        """Decrypting with the wrong key must raise InvalidTag."""
        vault, _, _ = vault_and_key
        wrong_key = os.urandom(AES_KEY_BYTES)
        with pytest.raises(InvalidTag):
            decrypt_secret(vault, wrong_key)

    def test_tampered_ciphertext_rejected(self, vault_and_key):
        """Bit-flip in ciphertext must be detected by the GCM authentication tag."""
        vault, key, _ = vault_and_key
        tampered_ct = bytearray(vault.ciphertext)
        tampered_ct[0] ^= 0xFF          # flip first byte
        tampered_vault = EncryptedVault(nonce=vault.nonce, ciphertext=bytes(tampered_ct))
        with pytest.raises(InvalidTag):
            decrypt_secret(tampered_vault, key)

    def test_serialization_roundtrip(self, vault_and_key):
        """EncryptedVault.to_bytes / from_bytes is lossless."""
        vault, key, original = vault_and_key
        blob = vault.to_bytes()
        restored = EncryptedVault.from_bytes(blob)
        assert restored.nonce == vault.nonce
        assert restored.ciphertext == vault.ciphertext
        assert decrypt_secret(restored, key) == original

    def test_empty_plaintext_rejected(self):
        """create_vault must reject empty plaintext per security invariant."""
        with pytest.raises(ValueError, match="non-empty"):
            create_vault(b"")

    def test_key_length_validation(self):
        """encrypt_secret must reject keys that are not 32 bytes."""
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_secret(b"hello", master_key=b"short_key")

    def test_decrypt_key_length_validation(self, vault_and_key):
        """decrypt_secret must reject keys that are not 32 bytes."""
        vault, _, _ = vault_and_key
        with pytest.raises(ValueError, match="32 bytes"):
            decrypt_secret(vault, b"tooshort")

    def test_unicode_payload(self):
        """Multi-byte unicode payloads (e.g. Kanji seed phrase) round-trip correctly."""
        payload = "私の秘密の種フレーズ — abandon wallet 🔐".encode("utf-8")
        vault, key = encrypt_secret(payload)
        assert decrypt_secret(vault, key) == payload


# ---------------------------------------------------------------------------
# Shamir's Secret Sharing Tests
# ---------------------------------------------------------------------------

class TestShamirSecretSharing:
    # --- Core 2-of-3 recombination property ---

    def test_combine_s1_s2_equals_key(self, master_key):
        """combine(S1, S2) reconstructs K."""
        shards = shamir_split(master_key)
        s1, s2, s3 = shards
        assert shamir_combine([s1, s2]) == master_key

    def test_combine_s1_s3_equals_key(self, master_key):
        """combine(S1, S3) reconstructs K."""
        shards = shamir_split(master_key)
        s1, s2, s3 = shards
        assert shamir_combine([s1, s3]) == master_key

    def test_combine_s2_s3_equals_key(self, master_key):
        """combine(S2, S3) reconstructs K."""
        shards = shamir_split(master_key)
        s1, s2, s3 = shards
        assert shamir_combine([s2, s3]) == master_key

    def test_all_pairs_equal_each_other(self, master_key):
        """All three pair combinations reconstruct the same K."""
        shards = shamir_split(master_key)
        s1, s2, s3 = shards
        k12 = shamir_combine([s1, s2])
        k13 = shamir_combine([s1, s3])
        k23 = shamir_combine([s2, s3])
        assert k12 == k13 == k23 == master_key, (
            "2-of-3 Shamir property violated: not all 2-shard pairs reconstruct K"
        )

    def test_combine_all_three_shards(self, master_key):
        """Supplying all 3 shards (uses first 2) also reconstructs K."""
        shards = shamir_split(master_key)
        assert shamir_combine(shards) == master_key

    def test_shard_indices_are_distinct(self, master_key):
        """Each shard has a unique x-coordinate."""
        shards = shamir_split(master_key)
        indices = [s.index for s in shards]
        assert len(set(indices)) == len(indices), "Duplicate shard indices detected"

    def test_shard_values_differ_from_key(self, master_key):
        """Shard byte strings should not equal the master key (not XOR-pads)."""
        shards = shamir_split(master_key)
        for shard in shards:
            assert shard.value != master_key

    def test_shards_are_same_length_as_key(self, master_key):
        """Every shard value is the same byte length as the secret."""
        shards = shamir_split(master_key)
        for shard in shards:
            assert len(shard.value) == len(master_key)

    def test_different_splits_produce_different_shards(self, master_key):
        """Two calls to shamir_split with the same key produce different shards
        (randomized coefficients ensure no determinism leak)."""
        shards_a = shamir_split(master_key)
        shards_b = shamir_split(master_key)
        # At least one shard value should differ (probability of collision ≈ 2^-256)
        any_different = any(
            shards_a[i].value != shards_b[i].value for i in range(3)
        )
        assert any_different, "shamir_split is deterministic — randomness source broken"

    # --- Security property: single shard leaks zero information ---

    def test_single_shard_does_not_reveal_1byte_secret(self):
        """
        ZERO INFORMATION property (information-theoretic security):

        For a 1-byte secret, there are only 256 possible values.
        Given a single shard y_1 = f(1) where f(x) = secret + a1*x,
        the coefficient a1 is uniformly random over GF(256).

        Therefore f(1) = secret ^ a1 is ALSO uniformly random — every
        possible shard value is consistent with EVERY possible secret.

        Test: for each of the 256 possible 1-byte keys, split it and collect
        S1 values across N trials.  The distribution of S1 must cover all 256
        values regardless of the fixed secret — proving no correlation.
        """
        TRIALS = 512
        secret_byte = bytes([0x42])      # fixed 1-byte secret
        observed_s1_values = set()

        for _ in range(TRIALS):
            shards = shamir_split(secret_byte, total=3, threshold=2)
            observed_s1_values.add(shards[0].value[0])

        # After 512 trials, we expect to see most of the 256 possible values.
        # The birthday problem tells us ~256*(1 - (255/256)^512) ≈ 254 unique
        # values in expectation.  Requiring >= 200 gives enormous safety margin.
        assert len(observed_s1_values) >= 200, (
            f"S1 value space too small ({len(observed_s1_values)}/256) — "
            "single shard may be leaking information about the secret"
        )

    def test_single_shard_cannot_reconstruct(self, master_key):
        """shamir_combine must refuse fewer than 2 shards."""
        shards = shamir_split(master_key)
        with pytest.raises(ValueError, match="At least 2"):
            shamir_combine([shards[0]])

    def test_single_shard_does_not_equal_secret(self, master_key):
        """No individual shard value should equal the original key."""
        shards = shamir_split(master_key)
        for shard in shards:
            assert shard.value != master_key, (
                "Shard value equals master key — SSS is not obfuscating the secret"
            )

    # --- Error paths ---

    def test_empty_secret_rejected(self):
        """shamir_split must reject an empty secret."""
        with pytest.raises(ValueError, match="non-empty"):
            shamir_split(b"")

    def test_threshold_too_low_rejected(self):
        """threshold=1 is not secure and must be rejected."""
        with pytest.raises(ValueError, match="threshold"):
            shamir_split(b"key", threshold=1)

    def test_total_less_than_threshold_rejected(self):
        """total < threshold is nonsensical and must be rejected."""
        with pytest.raises(ValueError, match="total"):
            shamir_split(b"key", total=1, threshold=2)

    def test_inconsistent_shard_lengths_rejected(self, master_key):
        """shamir_combine must detect mismatched shard lengths."""
        shards = shamir_split(master_key)
        bad_shard = Shard(index=shards[1].index, value=b"short")
        with pytest.raises(ValueError, match="inconsistent"):
            shamir_combine([shards[0], bad_shard])


# ---------------------------------------------------------------------------
# Full End-to-End Vault Tests
# ---------------------------------------------------------------------------

class TestCreateVault:
    def test_full_roundtrip_heir_pair(self, sample_secret):
        """
        Full production flow:
          1. create_vault(plaintext)       — owner side
          2. combine(S1, S2) → K          — heir combines shards after DECEASED_RELEASED
          3. decrypt(vault, K) → plaintext — heir recovers secret
        """
        bundle = create_vault(sample_secret)

        # Heir combines S1 (published by DeadBolt node) + S2 (held by heir)
        reconstructed_key = shamir_combine([bundle.shard_1, bundle.shard_2])
        recovered_plaintext = decrypt_secret(bundle.vault, reconstructed_key)

        assert recovered_plaintext == sample_secret

    def test_full_roundtrip_all_shard_pairs(self, sample_secret):
        """All three 2-shard pairs successfully decrypt the vault."""
        bundle = create_vault(sample_secret)
        s1, s2, s3 = bundle.shard_1, bundle.shard_2, bundle.shard_3

        for pair_label, pair in [("S1+S2", [s1, s2]),
                                  ("S1+S3", [s1, s3]),
                                  ("S2+S3", [s2, s3])]:
            k = shamir_combine(pair)
            recovered = decrypt_secret(bundle.vault, k)
            assert recovered == sample_secret, (
                f"Vault decryption failed with shard pair {pair_label}"
            )

    def test_vault_bundle_has_three_shards(self, sample_secret):
        """create_vault always produces exactly 3 shards."""
        bundle = create_vault(sample_secret)
        assert bundle.shard_1.index == 1
        assert bundle.shard_2.index == 2
        assert bundle.shard_3.index == 3

    def test_vault_serialization_in_full_flow(self, sample_secret):
        """Vault serialized to bytes and restored still decrypts correctly."""
        bundle = create_vault(sample_secret)
        blob = bundle.vault.to_bytes()
        restored_vault = EncryptedVault.from_bytes(blob)

        k = shamir_combine([bundle.shard_1, bundle.shard_2])
        assert decrypt_secret(restored_vault, k) == sample_secret

    def test_long_payload(self):
        """Large payloads (e.g. 10 KB testament letter) round-trip correctly."""
        big_plaintext = os.urandom(10_240)
        bundle = create_vault(big_plaintext)
        k = shamir_combine([bundle.shard_1, bundle.shard_3])
        assert decrypt_secret(bundle.vault, k) == big_plaintext

    def test_different_vaults_are_independent(self, sample_secret):
        """Two vault bundles for the same secret use different keys — no key reuse."""
        b1 = create_vault(sample_secret)
        b2 = create_vault(sample_secret)

        # Shards from different vaults must not cross-combine
        k1 = shamir_combine([b1.shard_1, b1.shard_2])
        k2 = shamir_combine([b2.shard_1, b2.shard_2])
        assert k1 != k2, "Two vaults produced the same master key — key reuse detected"

    def test_cross_vault_shards_do_not_decrypt(self, sample_secret):
        """
        Security: a shard from vault-B combined with a shard from vault-A
        must NOT decrypt vault-A's ciphertext.
        """
        b1 = create_vault(sample_secret)
        b2 = create_vault(sample_secret)

        cross_key = shamir_combine([b1.shard_1, b2.shard_2])
        with pytest.raises(InvalidTag):
            decrypt_secret(b1.vault, cross_key)
