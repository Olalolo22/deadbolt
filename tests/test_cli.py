"""
DeadBolt — Task 4: CLI End-to-End Tests
========================================

Tests the complete user lifecycle through the Click CLI using the
CliRunner (no terminal, no network, no real clock jumps).

Lifecycle covered
-----------------
  §1  init   — creates vault.json, prints Shard 2, validates config
  §2  status — renders terminal card; runs tick to update state
  §3  checkin — resets timer, refuses DECEASED_RELEASED, persists state
  §4  fast-forward — drives clock forward; correct state transitions
  §5  claim — heir reconstructs key; rejects pre-release vaults
  §6  End-to-end lifecycle — init → fast-forward (full death) → claim
  §7  Error paths — missing vault, bad shard, invalid args
"""

from __future__ import annotations

import json
import os
import re as _re
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Generator

import pytest
from click.testing import CliRunner

from src.cli import cli


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def tmp_vault_dir(tmp_path: Path) -> Path:
    """Return a fresh temporary directory for vault state."""
    return tmp_path / "vault"


def _base_args(vault_dir: Path) -> list:
    """Common CLI args to point at the temp vault directory."""
    return ["--vault-dir", str(vault_dir)]


def _init_vault(runner: CliRunner, vault_dir: Path,
                secret: str = "abandon abandon abandon about",
                interval_days: int = 10,
                max_missed: int = 3,
                grace_days: int = 14) -> None:
    """
    Helper: run `deadbolt init` with pre-set options (no interactive prompts).
    Asserts the command exits cleanly.
    """
    result = runner.invoke(cli, [
        *_base_args(vault_dir),
        "init",
        "--secret", secret,
        "--interval-days", str(interval_days),
        "--max-missed",    str(max_missed),
        "--grace-days",    str(grace_days),
        "--non-interactive",
    ])
    assert result.exit_code == 0, (
        f"init failed (exit {result.exit_code}):\n{result.output}"
    )


def _read_vault_json(vault_dir: Path) -> dict:
    return json.loads((vault_dir / "vault.json").read_text())


def _extract_shard2_from_output(output: str) -> str | None:
    """
    Extract the Shard 2 hex string from `deadbolt init` output.

    Rich wraps panel content lines with the box-drawing char '│' followed by
    a space, so a stripped line looks like '│ <hex>'.  We search for a
    contiguous run of exactly 64 lowercase hex chars anywhere in the output.
    The first match is Shard 2 (Shard 3 appears second in the output order).
    """
    matches = _re.findall(r'(?<![0-9a-f])([0-9a-f]{64})(?![0-9a-f])', output)
    return matches[0] if matches else None
    """
    Extract the Shard 2 hex string from `deadbolt init` output.

    Rich wraps panel content lines with the box-drawing char '│' followed by
    a space, so a stripped line looks like '│ <hex>'.  We search for a
    contiguous run of exactly 64 lowercase hex chars anywhere in the output.
    """
    matches = _re.findall(r'\b([0-9a-f]{64})\b', output)
    # The init command prints Shard 2 first (panel order), then Shard 3.
    # Return the first match.
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# §1 — init
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_vault_json(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        assert (tmp_vault_dir / "vault.json").exists()

    def test_vault_state_is_active(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"

    def test_encrypted_vault_hex_stored(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        data = _read_vault_json(tmp_vault_dir)
        assert len(data["encrypted_vault_hex"]) > 0

    def test_shard_1_stored(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        data = _read_vault_json(tmp_vault_dir)
        assert len(data["shard_1_hex"]) > 0

    def test_shard_2_printed_in_output(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret", "my seed phrase",
            "--non-interactive",
        ])
        assert "SHARD 2" in result.output or "HEIR" in result.output.upper()

    def test_shard_2_not_in_vault_json(self, runner, tmp_vault_dir):
        """Zero Custody: Shard 2 must never be persisted in vault.json."""
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret", "secret payload",
            "--non-interactive",
        ])
        # Extract the shard_2_hex from the output
        shard_2_candidate = _extract_shard2_from_output(result.output)

        data = _read_vault_json(tmp_vault_dir)
        raw_json = (tmp_vault_dir / "vault.json").read_text()

        if shard_2_candidate:
            assert shard_2_candidate not in raw_json, (
                "Zero Custody VIOLATED: Shard 2 found in vault.json"
            )

    def test_config_values_persisted(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=20, max_missed=2, grace_days=21)
        data = _read_vault_json(tmp_vault_dir)
        assert data["checkin_interval_days"] == 20
        assert data["max_missed_pings"]      == 2
        assert data["grace_period_days"]     == 21

    def test_missed_ping_count_starts_at_zero(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        data = _read_vault_json(tmp_vault_dir)
        assert data["missed_ping_count"] == 0

    def test_sim_clock_offset_starts_at_zero(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        data = _read_vault_json(tmp_vault_dir)
        assert data["sim_clock_offset_seconds"] == 0

    def test_grace_days_below_14_rejected(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret", "s",
            "--grace-days", "7",
            "--non-interactive",
        ])
        assert result.exit_code != 0

    def test_vault_id_included_in_output(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--vault-id", "my-test-vault",
            "--secret",   "some secret",
            "--non-interactive",
        ])
        assert "my-test-vault" in result.output

    def test_custom_vault_id_persisted(self, runner, tmp_vault_dir):
        runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--vault-id", "custom-id-123",
            "--secret",   "some secret",
            "--non-interactive",
        ])
        data = _read_vault_json(tmp_vault_dir)
        assert data["vault_id"] == "custom-id-123"


# ---------------------------------------------------------------------------
# §2 — status
# ---------------------------------------------------------------------------

class TestStatus:
    def test_status_exits_zero_on_active_vault(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert result.exit_code == 0

    def test_status_shows_active_state(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "ACTIVE" in result.output

    def test_status_shows_vault_id(self, runner, tmp_vault_dir):
        runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init", "--vault-id", "status-test", "--secret", "s", "--non-interactive",
        ])
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "status-test" in result.output

    def test_status_fails_without_vault(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert result.exit_code != 0

    def test_status_shows_ping_missed_after_fast_forward(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "11"])
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "PING_MISSED" in result.output

    def test_status_shows_grace_period_after_enough_misses(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "31"])
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "GRACE_PERIOD" in result.output or "PING_MISSED" in result.output

    def test_status_shows_deceased_released_after_full_cycle(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        # 10*3 + 14 + 5 = 69 days drives to DECEASED_RELEASED
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "DECEASED_RELEASED" in result.output or "DECEASED" in result.output


# ---------------------------------------------------------------------------
# §3 — checkin
# ---------------------------------------------------------------------------

class TestCheckin:
    def test_checkin_on_active_vault_succeeds(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        assert result.exit_code == 0
        assert "confirmed" in result.output.lower() or "✅" in result.output

    def test_checkin_resets_missed_pings(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3)
        # Miss one ping
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "11"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "PING_MISSED"
        assert data["missed_ping_count"] >= 1
        # Check in
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"
        assert data["missed_ping_count"] == 0

    def test_checkin_extends_next_due(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3)
        data_before = _read_vault_json(tmp_vault_dir)
        old_due = data_before["next_checkin_due"]
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        data_after = _read_vault_json(tmp_vault_dir)
        new_due = data_after["next_checkin_due"]
        assert new_due > old_due

    def test_checkin_on_deceased_vault_fails(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        assert result.exit_code != 0
        assert "DECEASED" in result.output.upper() or "terminal" in result.output.lower()

    def test_checkin_persists_updated_state(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"
        assert data["last_checkin_at"] is not None

    def test_checkin_during_grace_reverts_to_active(self, runner, tmp_vault_dir):
        """Security invariant: authenticated check-in during grace → ACTIVE."""
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        # Drive into grace (3 misses = 30 days + 1) then 5 days into grace window
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "36"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "GRACE_PERIOD"
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"
        assert data["missed_ping_count"] == 0


# ---------------------------------------------------------------------------
# §4 — fast-forward
# ---------------------------------------------------------------------------

class TestFastForward:
    def test_fast_forward_advances_offset(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "5"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["sim_clock_offset_seconds"] == 5 * 86400

    def test_fast_forward_missing_days_fails(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward"])
        assert result.exit_code != 0

    def test_fast_forward_zero_days_fails(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "0"])
        assert result.exit_code != 0

    def test_fast_forward_one_miss_transitions_state(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "11"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "PING_MISSED"

    def test_fast_forward_max_misses_enters_grace(self, runner, tmp_vault_dir):
        """After 3 misses (interval=10 → 31 days) state must be GRACE_PERIOD."""
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "31"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "GRACE_PERIOD"

    def test_fast_forward_past_grace_reaches_deceased(self, runner, tmp_vault_dir):
        """Past grace window → DECEASED_RELEASED."""
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "DECEASED_RELEASED"
        assert data["released_at"] is not None

    def test_fast_forward_is_cumulative(self, runner, tmp_vault_dir):
        """Two fast-forwards add their offsets."""
        _init_vault(runner, tmp_vault_dir)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "5"])
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "3"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["sim_clock_offset_seconds"] == 8 * 86400

    def test_fast_forward_prints_state_transitions(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        assert result.exit_code == 0
        # Should mention at least one state name in the transitions panel
        output_upper = result.output.upper()
        assert any(s in output_upper
                   for s in ["PING_MISSED", "GRACE_PERIOD", "DECEASED_RELEASED"])

    def test_fast_forward_deceased_vault_ticks_are_no_op(self, runner, tmp_vault_dir):
        """After release, more fast-forwarding doesn't change released_at."""
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        data_first = _read_vault_json(tmp_vault_dir)
        released_at_first = data_first["released_at"]
        # Fast-forward again on a released vault
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "100"])
        data_second = _read_vault_json(tmp_vault_dir)
        assert data_second["state"] == "DECEASED_RELEASED"
        assert data_second["released_at"] == released_at_first


# ---------------------------------------------------------------------------
# §5 — claim
# ---------------------------------------------------------------------------

class TestClaim:
    def _setup_deceased_vault(self, runner: CliRunner, tmp_vault_dir: Path,
                              secret: str = "inherit this seed phrase") -> str:
        """
        Initialize a vault, fast-forward to DECEASED_RELEASED, and return Shard 2 hex.
        Shard 2 is extracted from the init output.
        """
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret", secret,
            "--interval-days", "10",
            "--max-missed",    "3",
            "--grace-days",    "14",
            "--non-interactive",
        ])
        assert result.exit_code == 0

        # Extract shard_2_hex from init output (long hex string on its own line)
        shard_2_hex = _extract_shard2_from_output(result.output)
        assert shard_2_hex is not None, (
            f"Could not extract Shard 2 from init output:\n{result.output}"
        )

        # Fast-forward past the full death cycle
        runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "fast-forward", "--days", "75",
        ])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "DECEASED_RELEASED", (
            f"Expected DECEASED_RELEASED after fast-forward, got {data['state']}"
        )
        return shard_2_hex

    def test_claim_succeeds_with_correct_shard_2(self, runner, tmp_vault_dir):
        secret = "abandon wallet seed phrase for my heir"
        shard_2 = self._setup_deceased_vault(runner, tmp_vault_dir, secret)
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", shard_2,
        ])
        assert result.exit_code == 0
        assert secret in result.output

    def test_claim_prints_decrypted_secret(self, runner, tmp_vault_dir):
        secret = "my private key: xprv9s21ZrQH143K..."
        shard_2 = self._setup_deceased_vault(runner, tmp_vault_dir, secret)
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", shard_2,
        ])
        assert secret in result.output

    def test_claim_rejected_on_active_vault(self, runner, tmp_vault_dir):
        """Shard 1 is locked while vault is ACTIVE."""
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", "a" * 64,
        ])
        assert result.exit_code != 0
        assert "DECEASED" in result.output.upper() or "not yet" in result.output.lower()

    def test_claim_rejected_on_ping_missed_vault(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "11"])
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", "a" * 64,
        ])
        assert result.exit_code != 0

    def test_claim_rejected_on_grace_period_vault(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "31"])
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", "a" * 64,
        ])
        assert result.exit_code != 0

    def test_claim_fails_with_wrong_shard_2(self, runner, tmp_vault_dir):
        self._setup_deceased_vault(runner, tmp_vault_dir)
        wrong_shard = "0" * 64   # all zeros — wrong shard
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", wrong_shard,
        ])
        assert result.exit_code != 0

    def test_claim_shard_1_published_in_output(self, runner, tmp_vault_dir):
        """Once DECEASED_RELEASED, Shard 1 is printed openly in claim output."""
        shard_2 = self._setup_deceased_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", shard_2,
        ])
        data = _read_vault_json(tmp_vault_dir)
        shard_1_hex = data["shard_1_hex"]
        assert shard_1_hex in result.output

    def test_claim_shard_1_not_in_output_before_release(self, runner, tmp_vault_dir):
        """Shard 1 must NOT appear in status/checkin output on a live vault."""
        _init_vault(runner, tmp_vault_dir)
        status_result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        data = _read_vault_json(tmp_vault_dir)
        shard_1_hex = data["shard_1_hex"]
        assert shard_1_hex not in status_result.output


# ---------------------------------------------------------------------------
# §6 — Full end-to-end lifecycle
# ---------------------------------------------------------------------------

class TestFullLifecycle:
    def test_complete_death_and_inheritance_cycle(self, runner, tmp_vault_dir):
        """
        Full lifecycle:
          1. deadbolt init       → vault created, Shard 2 printed
          2. deadbolt checkin    → timer reset (owner is alive)
          3. deadbolt status     → ACTIVE
          4. deadbolt fast-forward --days 75 → DECEASED_RELEASED
          5. deadbolt claim      → plaintext recovered by heir
        """
        secret = "bitcoin seed: zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"

        # 1. Init
        init_result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret",        secret,
            "--interval-days", "10",
            "--max-missed",    "3",
            "--grace-days",    "14",
            "--non-interactive",
        ])
        assert init_result.exit_code == 0

        # Extract Shard 2
        shard_2_hex = _extract_shard2_from_output(init_result.output)
        assert shard_2_hex is not None

        # 2. Check in (owner alive)
        checkin_result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        assert checkin_result.exit_code == 0

        # 3. Status → ACTIVE
        status_result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert "ACTIVE" in status_result.output

        # 4. Fast-forward past full death cycle
        ff_result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "fast-forward", "--days", "75",
        ])
        assert ff_result.exit_code == 0
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "DECEASED_RELEASED"

        # 5. Heir claims inheritance
        claim_result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", shard_2_hex,
        ])
        assert claim_result.exit_code == 0
        assert secret in claim_result.output

    def test_grace_period_rescue_lifecycle(self, runner, tmp_vault_dir):
        """
        Owner misses pings, enters grace, but rescues on day 10 of 14-day window.
        Vault reverts to ACTIVE and heir CANNOT claim.
        """
        secret = "rescued seed phrase abc123"

        init_result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "init",
            "--secret",        secret,
            "--interval-days", "10",
            "--max-missed",    "3",
            "--grace-days",    "14",
            "--non-interactive",
        ])
        assert init_result.exit_code == 0

        # Extract Shard 2 (for later attempted claim)
        shard_2_hex = _extract_shard2_from_output(init_result.output)

        # Fast-forward into grace period (3 misses = 31 days, then 10 days into grace)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "36"])
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "GRACE_PERIOD"

        # Owner rescues during grace
        checkin_result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        assert checkin_result.exit_code == 0
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"
        assert data["missed_ping_count"] == 0

        # Heir attempts to claim — must be REJECTED because vault is ACTIVE
        if shard_2_hex:
            claim_result = runner.invoke(cli, [
                *_base_args(tmp_vault_dir),
                "claim",
                "--shard-2", shard_2_hex,
            ])
            assert claim_result.exit_code != 0

    def test_multiple_fast_forwards_and_checkins(self, runner, tmp_vault_dir):
        """
        Interleaved fast-forwards and check-ins demonstrate the owner repeatedly
        surviving close calls without ever reaching DECEASED_RELEASED.
        """
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)

        for _ in range(3):
            # Advance to just before max misses (2 misses = 21 days)
            runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "21"])
            data = _read_vault_json(tmp_vault_dir)
            # Should be PING_MISSED (2 misses), not GRACE_PERIOD
            assert data["state"] in ("PING_MISSED", "ACTIVE")
            # Rescue
            runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
            data = _read_vault_json(tmp_vault_dir)
            assert data["state"] == "ACTIVE"
            assert data["missed_ping_count"] == 0

        # Confirm never released
        data = _read_vault_json(tmp_vault_dir)
        assert data["state"] == "ACTIVE"
        assert data["released_at"] is None


# ---------------------------------------------------------------------------
# §7 — Error paths
# ---------------------------------------------------------------------------

class TestErrorPaths:
    def test_status_without_vault_errors(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "status"])
        assert result.exit_code != 0

    def test_checkin_without_vault_errors(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "checkin"])
        assert result.exit_code != 0

    def test_fast_forward_without_vault_errors(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "5"])
        assert result.exit_code != 0

    def test_claim_without_vault_errors(self, runner, tmp_vault_dir):
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim", "--shard-2", "a" * 64,
        ])
        assert result.exit_code != 0

    def test_fast_forward_non_integer_days_errors(self, runner, tmp_vault_dir):
        _init_vault(runner, tmp_vault_dir)
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "fast-forward", "--days", "banana",
        ])
        assert result.exit_code != 0

    def test_claim_bad_shard_hex_errors(self, runner, tmp_vault_dir):
        """Non-hex Shard 2 input must fail gracefully."""
        _init_vault(runner, tmp_vault_dir, interval_days=10, max_missed=3, grace_days=14)
        runner.invoke(cli, [*_base_args(tmp_vault_dir), "fast-forward", "--days", "75"])
        result = runner.invoke(cli, [
            *_base_args(tmp_vault_dir),
            "claim",
            "--shard-2", "not-valid-hex-!!!",
        ])
        assert result.exit_code != 0
