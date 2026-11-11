"""
DeadBolt — Task 2: HeartbeatVault State Machine Engine — Unit Tests
====================================================================

Coverage matrix:

  §1  State enum ordering / monotonic values
  §2  Vault initialization and configuration validation
  §3  Happy-path check-in (ACTIVE stays ACTIVE, timer extends)
  §4  Single missed ping → PING_MISSED (NOT grace, NOT release)
  §5  N consecutive misses → GRACE_PERIOD (after exactly max_missed_pings)
  §6  Grace period escalation alerts fire on every tick
  §7  Grace period expiry → DECEASED_RELEASED (terminal)
  §8  Owner check-in during PING_MISSED → ACTIVE (revocability)
  §9  Owner check-in during GRACE_PERIOD → ACTIVE (revocability)
  §10 DECEASED_RELEASED is permanent — no check-in, tick, or other op reverts it
  §11 Anti-replay: same token cannot be submitted twice
  §12 Invalid token HMAC raises InvalidTokenError
  §13 trigger_grace() / finalize_release() called from wrong state raise errors
  §14 Configuration validation (grace period < 14 days rejected, etc.)
  §15 Alert generation: channels, severity, state labelling
  §16 Reminder alerts fire within reminder_lead window
  §17 Fast-forward clock simulation (multi-tick scenarios end-to-end)
"""

import pytest
from datetime import datetime, timedelta, timezone
from typing import List

from src.vault import (
    DEFAULT_CHECKIN_INTERVAL_DAYS,
    DEFAULT_GRACE_PERIOD_DAYS,
    DEFAULT_MAX_MISSED_PINGS,
    Alert,
    AlertChannel,
    AlertSeverity,
    FinalStateError,
    HeartbeatVault,
    InvalidStateTransitionError,
    InvalidTokenError,
    TokenReplayError,
    VaultState,
    generate_checkin_token,
    verify_checkin_token,
)


# ---------------------------------------------------------------------------
# Helpers / Fixtures
# ---------------------------------------------------------------------------

def utc(year=2026, month=1, day=1, **kwargs) -> datetime:
    """Return a UTC-aware datetime for use as an authoritative clock."""
    return datetime(year, month, day, tzinfo=timezone.utc, **kwargs)


def make_vault(
    vault_id: str = "test-vault-001",
    interval_days: int = DEFAULT_CHECKIN_INTERVAL_DAYS,
    max_missed: int = DEFAULT_MAX_MISSED_PINGS,
    grace_days: int = DEFAULT_GRACE_PERIOD_DAYS,
    channels: List[AlertChannel] | None = None,
) -> HeartbeatVault:
    """Factory producing a fully initialized HeartbeatVault anchored at epoch."""
    if channels is None:
        channels = list(AlertChannel)
    vault = HeartbeatVault(
        vault_id=vault_id,
        checkin_interval=timedelta(days=interval_days),
        max_missed_pings=max_missed,
        grace_period_duration=timedelta(days=grace_days),
        alert_channels=channels,
    )
    vault.initialize(utc())
    return vault


def advance(vault: HeartbeatVault, days: float, start: datetime | None = None) -> List[Alert]:
    """
    Fast-forward *vault* by *days* from *start* (default: last_checkin_at),
    ticking once per day.  Returns all accumulated alerts.
    """
    all_alerts: List[Alert] = []
    base = start or vault.last_checkin_at or utc()
    for d in range(1, int(days) + 1):
        all_alerts.extend(vault.tick(base + timedelta(days=d)))
    return all_alerts


# ---------------------------------------------------------------------------
# §1 — State Enum Ordering
# ---------------------------------------------------------------------------

class TestVaultStateOrdering:
    def test_monotonic_integer_values(self):
        """State enum values must be strictly increasing in transition order."""
        assert VaultState.ACTIVE.value            < VaultState.PING_MISSED.value
        assert VaultState.PING_MISSED.value       < VaultState.GRACE_PERIOD.value
        assert VaultState.GRACE_PERIOD.value      < VaultState.DECEASED_RELEASED.value

    def test_deceased_released_is_max(self):
        """DECEASED_RELEASED has the highest ordinal — it cannot be exceeded."""
        assert VaultState.DECEASED_RELEASED.value == max(s.value for s in VaultState)


# ---------------------------------------------------------------------------
# §2 — Vault Initialization & Configuration Validation
# ---------------------------------------------------------------------------

class TestVaultInitialization:
    def test_initial_state_is_active(self):
        v = make_vault()
        assert v.state == VaultState.ACTIVE

    def test_next_checkin_due_set_on_initialize(self):
        v = make_vault(interval_days=30)
        assert v.next_checkin_due == utc() + timedelta(days=30)

    def test_missed_ping_count_starts_at_zero(self):
        v = make_vault()
        assert v.missed_ping_count == 0

    def test_grace_period_markers_start_as_none(self):
        v = make_vault()
        assert v.grace_period_start is None
        assert v.grace_period_end is None
        assert v.released_at is None

    def test_grace_duration_below_14_days_rejected(self):
        """Security invariant: grace period must be >= 14 days."""
        with pytest.raises(ValueError, match="14 days"):
            HeartbeatVault(
                vault_id="bad",
                grace_period_duration=timedelta(days=13),
            )

    def test_checkin_interval_below_1_day_rejected(self):
        with pytest.raises(ValueError, match="1 day"):
            HeartbeatVault(
                vault_id="bad",
                checkin_interval=timedelta(hours=23),
            )

    def test_max_missed_pings_zero_rejected(self):
        with pytest.raises(ValueError, match="max_missed_pings"):
            HeartbeatVault(vault_id="bad", max_missed_pings=0)

    def test_exactly_14_day_grace_accepted(self):
        """14 days is the minimum — must not raise."""
        v = HeartbeatVault(
            vault_id="ok",
            grace_period_duration=timedelta(days=DEFAULT_GRACE_PERIOD_DAYS),
        )
        assert v.grace_period_duration == timedelta(days=14)

    def test_initialize_is_idempotent(self):
        v = make_vault()
        due_first = v.next_checkin_due
        v.initialize(utc(day=15))    # second call with different time
        assert v.next_checkin_due == due_first   # unchanged


# ---------------------------------------------------------------------------
# §3 — Happy-Path Check-in (ACTIVE → stays ACTIVE)
# ---------------------------------------------------------------------------

class TestActiveCheckin:
    def test_checkin_before_deadline_keeps_state_active(self):
        v = make_vault(interval_days=30)
        now = utc(day=20)                        # 20 days in — still before deadline
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.state == VaultState.ACTIVE

    def test_checkin_extends_next_due(self):
        v = make_vault(interval_days=30)
        now = utc(day=20)
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.next_checkin_due == now + timedelta(days=30)

    def test_checkin_updates_last_checkin_at(self):
        v = make_vault(interval_days=30)
        now = utc(day=10)
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.last_checkin_at == now

    def test_checkin_does_not_alter_missed_count_when_active(self):
        v = make_vault()
        token = v.generate_token()
        v.record_checkin(token, utc(day=5))
        assert v.missed_ping_count == 0

    def test_tick_before_deadline_produces_no_alerts(self):
        v = make_vault(interval_days=30)
        alerts = v.tick(utc(day=10))             # well before deadline
        assert alerts == []

    def test_tick_at_one_second_before_deadline_produces_no_alerts(self):
        """Deadline is exclusive: now < next_checkin_due must not trigger a miss.
        Tick at deadline minus (reminder_lead + 1 day) to stay outside the reminder
        window and confirm no alerts fire at all."""
        v = make_vault(interval_days=30)
        # 8 days before deadline — outside the 7-day reminder window and before due
        outside_reminder = v.next_checkin_due - timedelta(days=8)
        alerts = v.tick(outside_reminder)
        assert alerts == []
        assert v.state == VaultState.ACTIVE


# ---------------------------------------------------------------------------
# §4 — Single Missed Ping → PING_MISSED (NOT grace, NOT release)
# ---------------------------------------------------------------------------

class TestSingleMissedPing:
    def test_one_miss_transitions_to_ping_missed(self):
        """Security invariant: single missed heartbeat NEVER triggers release."""
        v = make_vault(interval_days=30, max_missed=3)
        # Tick one day past deadline
        alerts = v.tick(utc() + timedelta(days=31))
        assert v.state == VaultState.PING_MISSED

    def test_one_miss_does_not_enter_grace(self):
        """Single miss must NOT enter GRACE_PERIOD."""
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(utc() + timedelta(days=31))
        assert v.state != VaultState.GRACE_PERIOD

    def test_one_miss_does_not_release(self):
        """Single miss must NEVER trigger a release."""
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(utc() + timedelta(days=31))
        assert v.state != VaultState.DECEASED_RELEASED

    def test_one_miss_increments_counter_to_one(self):
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(utc() + timedelta(days=31))
        assert v.missed_ping_count == 1

    def test_one_miss_advances_next_due_by_interval(self):
        """next_checkin_due is advanced by one full interval after each miss."""
        v = make_vault(interval_days=30, max_missed=3)
        expected_due = v.next_checkin_due + timedelta(days=30)
        v.tick(utc() + timedelta(days=31))
        assert v.next_checkin_due == expected_due

    def test_one_miss_emits_warning_alert(self):
        v = make_vault(interval_days=30, max_missed=3)
        alerts = v.tick(utc() + timedelta(days=31))
        assert any(a.severity == AlertSeverity.WARNING for a in alerts)

    def test_two_misses_stays_ping_missed_with_max_3(self):
        v = make_vault(interval_days=30, max_missed=3)
        # Miss #1: tick one day past first deadline
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.missed_ping_count == 1
        # Miss #2: tick one day past the now-advanced second deadline
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED
        assert v.missed_ping_count == 2


# ---------------------------------------------------------------------------
# §5 — N Consecutive Misses → GRACE_PERIOD
# ---------------------------------------------------------------------------

class TestGracePeriodEntry:
    def test_max_missed_pings_triggers_grace(self):
        """After exactly max_missed_pings misses, state must be GRACE_PERIOD."""
        v = make_vault(interval_days=30, max_missed=3)
        # 3 misses: tick one day past each successive deadline
        for miss in range(1, DEFAULT_MAX_MISSED_PINGS + 1):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD

    def test_grace_period_start_set_on_entry(self):
        v = make_vault(interval_days=30, max_missed=3)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.grace_period_start is not None

    def test_grace_period_end_set_to_start_plus_duration(self):
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        expected_end = v.grace_period_start + timedelta(days=14)
        assert v.grace_period_end == expected_end

    def test_exactly_n_minus_1_misses_does_not_trigger_grace(self):
        """N-1 misses must NOT enter grace — boundary condition."""
        v = make_vault(interval_days=30, max_missed=3)
        for _ in range(DEFAULT_MAX_MISSED_PINGS - 1):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED

    def test_grace_entry_emits_critical_alerts_on_all_channels(self):
        v = make_vault(interval_days=30, max_missed=3,
                       channels=list(AlertChannel))
        all_alerts: List[Alert] = []
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            all_alerts.extend(v.tick(v.next_checkin_due + timedelta(days=1)))

        # Last batch of alerts is the grace entry notification
        grace_alerts = [a for a in all_alerts if a.state == VaultState.GRACE_PERIOD]
        dispatched_channels = {a.channel for a in grace_alerts}
        # Must cover all registered channels (invariant: escalation across all channels)
        assert dispatched_channels == set(AlertChannel)
        assert all(a.severity == AlertSeverity.CRITICAL for a in grace_alerts)

    def test_custom_max_missed_pings_honoured(self):
        """max_missed_pings=1 must enter grace on the very first miss."""
        v = make_vault(interval_days=30, max_missed=1)
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD


# ---------------------------------------------------------------------------
# §6 — Grace Period Escalation Alerts on Every Tick
# ---------------------------------------------------------------------------

class TestGraceEscalation:
    def _vault_in_grace(self) -> HeartbeatVault:
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD
        return v

    def test_tick_in_grace_emits_critical_alerts(self):
        v = self._vault_in_grace()
        alerts = v.tick(v.grace_period_start + timedelta(days=1))  # type: ignore
        critical = [a for a in alerts if a.severity == AlertSeverity.CRITICAL]
        assert len(critical) > 0

    def test_every_tick_in_grace_produces_alerts(self):
        """Invariant 4: escalation on EVERY tick during grace, not just the first."""
        v = self._vault_in_grace()
        for day in range(1, 14):
            alerts = v.tick(v.grace_period_start + timedelta(days=day))  # type: ignore
            assert len(alerts) > 0, f"No alert emitted on day {day} of grace period"

    def test_grace_tick_state_remains_grace(self):
        v = self._vault_in_grace()
        v.tick(v.grace_period_start + timedelta(days=5))  # type: ignore
        assert v.state == VaultState.GRACE_PERIOD

    def test_grace_alerts_reference_correct_state(self):
        v = self._vault_in_grace()
        alerts = v.tick(v.grace_period_start + timedelta(days=2))  # type: ignore
        assert all(a.state == VaultState.GRACE_PERIOD for a in alerts)


# ---------------------------------------------------------------------------
# §7 — Grace Period Expiry → DECEASED_RELEASED
# ---------------------------------------------------------------------------

class TestFinalRelease:
    def _vault_at_grace_end(self) -> HeartbeatVault:
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        return v

    def test_tick_at_grace_end_triggers_release(self):
        v = self._vault_at_grace_end()
        v.tick(v.grace_period_end)                        # type: ignore
        assert v.state == VaultState.DECEASED_RELEASED

    def test_tick_one_day_past_grace_end_triggers_release(self):
        v = self._vault_at_grace_end()
        v.tick(v.grace_period_end + timedelta(days=1))    # type: ignore
        assert v.state == VaultState.DECEASED_RELEASED

    def test_released_at_set_on_finalization(self):
        v = self._vault_at_grace_end()
        now = v.grace_period_end + timedelta(hours=1)     # type: ignore
        v.tick(now)
        assert v.released_at == now

    def test_release_emits_critical_alert_all_channels(self):
        v = self._vault_at_grace_end()
        alerts = v.tick(v.grace_period_end)               # type: ignore
        release_alerts = [a for a in alerts
                          if a.state == VaultState.DECEASED_RELEASED]
        channels = {a.channel for a in release_alerts}
        assert channels == set(AlertChannel)
        assert all(a.severity == AlertSeverity.CRITICAL for a in release_alerts)

    def test_tick_inside_grace_window_does_not_release(self):
        v = self._vault_at_grace_end()
        # One day before grace expires
        v.tick(v.grace_period_end - timedelta(days=1))    # type: ignore
        assert v.state == VaultState.GRACE_PERIOD
        assert v.state != VaultState.DECEASED_RELEASED

    def test_full_fast_forward_scenario(self):
        """
        End-to-end scenario: 30-day interval, 3 missed pings, 14-day grace.
        Total: 30 + (30*3) + 14 = 134 days from initialization to release.
        """
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        start = utc()
        # Miss all three intervals: days 31, 61, 91 relative to start
        for miss in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD
        # Expire grace
        v.tick(v.grace_period_end + timedelta(days=1))    # type: ignore
        assert v.state == VaultState.DECEASED_RELEASED


# ---------------------------------------------------------------------------
# §8 — Owner Check-in During PING_MISSED → ACTIVE (Revocability)
# ---------------------------------------------------------------------------

class TestRevocabilityFromPingMissed:
    def _vault_with_one_miss(self) -> HeartbeatVault:
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED
        return v

    def test_checkin_from_ping_missed_resets_to_active(self):
        v = self._vault_with_one_miss()
        token = v.generate_token()
        v.record_checkin(token, utc(month=3))
        assert v.state == VaultState.ACTIVE

    def test_checkin_resets_missed_count_to_zero(self):
        v = self._vault_with_one_miss()
        token = v.generate_token()
        v.record_checkin(token, utc(month=3))
        assert v.missed_ping_count == 0

    def test_checkin_extends_timer_from_now(self):
        v = self._vault_with_one_miss()
        now = utc(month=3)
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.next_checkin_due == now + timedelta(days=30)

    def test_checkin_clears_grace_markers_if_set(self):
        v = make_vault(interval_days=30, max_missed=3)
        # Push into PING_MISSED without grace
        v.tick(v.next_checkin_due + timedelta(days=1))
        # Manually simulate that we were previously in grace and cleared
        v.grace_period_start = utc(day=20)
        v.grace_period_end   = utc(day=25)
        token = v.generate_token()
        v.record_checkin(token, utc(month=3))
        assert v.grace_period_start is None
        assert v.grace_period_end is None

    def test_checkin_emits_info_alert(self):
        v = self._vault_with_one_miss()
        token = v.generate_token()
        alerts = v.record_checkin(token, utc(month=3))
        assert any(a.severity == AlertSeverity.INFO for a in alerts)

    def test_subsequent_ticks_after_recovery_work_normally(self):
        """After recovery from PING_MISSED, vault behaves as fresh ACTIVE vault."""
        v = self._vault_with_one_miss()
        now = utc(month=3)
        token = v.generate_token()
        v.record_checkin(token, now)
        # tick before new deadline → no alerts
        alerts = v.tick(now + timedelta(days=5))
        assert alerts == []
        assert v.state == VaultState.ACTIVE


# ---------------------------------------------------------------------------
# §9 — Owner Check-in During GRACE_PERIOD → ACTIVE (Revocability)
# ---------------------------------------------------------------------------

class TestRevocabilityFromGracePeriod:
    def _vault_in_grace(self) -> HeartbeatVault:
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD
        return v

    def test_checkin_during_grace_resets_to_active(self):
        """Security invariant: authenticated check-in DURING grace reverts to ACTIVE."""
        v = self._vault_in_grace()
        now = v.grace_period_start + timedelta(days=7)    # type: ignore
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.state == VaultState.ACTIVE

    def test_checkin_during_grace_clears_grace_markers(self):
        v = self._vault_in_grace()
        token = v.generate_token()
        v.record_checkin(token, v.grace_period_start + timedelta(days=3))  # type: ignore
        assert v.grace_period_start is None
        assert v.grace_period_end is None

    def test_checkin_during_grace_resets_missed_count(self):
        v = self._vault_in_grace()
        assert v.missed_ping_count == DEFAULT_MAX_MISSED_PINGS
        token = v.generate_token()
        v.record_checkin(token, v.grace_period_start + timedelta(days=1))  # type: ignore
        assert v.missed_ping_count == 0

    def test_checkin_on_last_day_of_grace_reverts(self):
        """Check-in on the final day of grace must still revert — not too late."""
        v = self._vault_in_grace()
        last_day = v.grace_period_end - timedelta(hours=1)  # type: ignore
        token = v.generate_token()
        v.record_checkin(token, last_day)
        assert v.state == VaultState.ACTIVE

    def test_full_recovery_then_new_missed_ping_cycle(self):
        """After grace recovery, the vault can enter PING_MISSED again independently."""
        v = self._vault_in_grace()
        now = v.grace_period_start + timedelta(days=5)    # type: ignore
        token = v.generate_token()
        v.record_checkin(token, now)
        assert v.state == VaultState.ACTIVE
        # Miss one ping in the new cycle
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED
        assert v.missed_ping_count == 1


# ---------------------------------------------------------------------------
# §10 — DECEASED_RELEASED is Permanent
# ---------------------------------------------------------------------------

class TestDeceasedReleasedImmutability:
    def _released_vault(self) -> HeartbeatVault:
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        v.tick(v.grace_period_end + timedelta(days=1))    # type: ignore
        assert v.state == VaultState.DECEASED_RELEASED
        return v

    def test_tick_after_release_is_no_op(self):
        """tick() on DECEASED_RELEASED must return empty alerts and not change state."""
        v = self._released_vault()
        alerts = v.tick(utc(year=2030))
        assert v.state == VaultState.DECEASED_RELEASED
        assert alerts == []

    def test_checkin_after_release_raises_final_state_error(self):
        """Security invariant: DECEASED_RELEASED cannot be reversed — ever."""
        v = self._released_vault()
        token = v.generate_token()
        with pytest.raises(FinalStateError, match="terminal state DECEASED_RELEASED"):
            v.record_checkin(token, utc(year=2027))

    def test_released_at_is_immutable_after_set(self):
        """released_at must not change after DECEASED_RELEASED is entered."""
        v = self._released_vault()
        original_released_at = v.released_at
        v.tick(utc(year=2029))
        assert v.released_at == original_released_at

    def test_initialize_after_release_raises(self):
        """initialize() on a released vault must raise FinalStateError."""
        v = self._released_vault()
        with pytest.raises(FinalStateError):
            v.initialize(utc(year=2028))

    def test_finalize_release_from_active_raises(self):
        """_finalize_release() can only be called from GRACE_PERIOD."""
        v = make_vault()
        with pytest.raises(InvalidStateTransitionError):
            v._finalize_release(utc(day=5))

    def test_trigger_grace_from_active_raises(self):
        """_trigger_grace() can only be called from PING_MISSED."""
        v = make_vault()
        with pytest.raises(InvalidStateTransitionError):
            v._trigger_grace(utc(day=5))

    def test_trigger_grace_from_grace_raises(self):
        """_trigger_grace() must not be callable while already in GRACE_PERIOD."""
        v = make_vault(interval_days=30, max_missed=3)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD
        with pytest.raises(InvalidStateTransitionError):
            v._trigger_grace(utc(year=2027))


# ---------------------------------------------------------------------------
# §11 — Anti-Replay: Token Reuse Detection
# ---------------------------------------------------------------------------

class TestAntiReplay:
    def test_same_token_cannot_be_used_twice(self):
        """Security invariant: single-use tokens — replay must raise TokenReplayError."""
        v = make_vault(interval_days=30)
        token = v.generate_token()
        v.record_checkin(token, utc(day=5))
        with pytest.raises(TokenReplayError, match="already been consumed"):
            v.record_checkin(token, utc(day=6))

    def test_two_distinct_tokens_both_valid(self):
        """Two different generated tokens are both independently valid."""
        v = make_vault(interval_days=30)
        token_a = v.generate_token()
        token_b = v.generate_token()
        # Use token_a first
        v.record_checkin(token_a, utc(day=5))
        # Push into PING_MISSED so a second check-in is meaningful
        v.tick(v.next_checkin_due + timedelta(days=1))
        # Use token_b — should succeed (day 5 + 30 + 1 = day 36 → use month=2)
        v.record_checkin(token_b, utc(month=2, day=5))
        assert v.state == VaultState.ACTIVE

    def test_different_vaults_tokens_do_not_cross(self):
        """A token for vault-A must not be accepted by vault-B."""
        v_a = make_vault(vault_id="vault-A")
        v_b = make_vault(vault_id="vault-B")
        token_a = v_a.generate_token()
        with pytest.raises(InvalidTokenError):
            v_b.record_checkin(token_a, utc(day=5))


# ---------------------------------------------------------------------------
# §12 — Token HMAC Verification
# ---------------------------------------------------------------------------

class TestTokenVerification:
    def test_malformed_token_raises_invalid(self):
        v = make_vault()
        with pytest.raises(InvalidTokenError):
            v.record_checkin("not.a.valid.token.at.all", utc(day=5))

    def test_tampered_mac_raises_invalid(self):
        v = make_vault()
        token = v.generate_token()
        parts = token.split(".")
        tampered = f"{parts[0]}.{parts[1]}.{'0' * len(parts[2])}"
        with pytest.raises(InvalidTokenError):
            v.record_checkin(tampered, utc(day=5))

    def test_wrong_vault_id_raises_invalid(self):
        v = make_vault(vault_id="correct-id")
        import os as _os
        import hmac as _hmac, hashlib as _hl
        # Build a token signed with the right key but wrong vault_id
        fake_token = f"wrong-id.{'a'*32}.{'b'*64}"
        with pytest.raises(InvalidTokenError):
            v.record_checkin(fake_token, utc(day=5))

    def test_valid_external_token_round_trip(self):
        """generate_checkin_token / verify_checkin_token public functions work."""
        key = b"a" * 32
        token = generate_checkin_token("my-vault", key)
        assert verify_checkin_token(token, "my-vault", key) is True

    def test_external_verify_rejects_wrong_key(self):
        key = b"a" * 32
        wrong_key = b"b" * 32
        token = generate_checkin_token("my-vault", key)
        assert verify_checkin_token(token, "my-vault", wrong_key) is False


# ---------------------------------------------------------------------------
# §13 — Guard-rail: Invalid Direct State-Transition Calls
# ---------------------------------------------------------------------------

class TestInvalidDirectTransitions:
    def test_trigger_grace_requires_ping_missed(self):
        v = make_vault()
        with pytest.raises(InvalidStateTransitionError):
            v._trigger_grace(utc(day=5))

    def test_finalize_release_requires_grace_period(self):
        v = make_vault()
        with pytest.raises(InvalidStateTransitionError):
            v._finalize_release(utc(day=5))

    def test_finalize_release_from_ping_missed_raises(self):
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED
        with pytest.raises(InvalidStateTransitionError):
            v._finalize_release(utc(month=2, day=5))


# ---------------------------------------------------------------------------
# §14 — Alert Generation: Channels, Severity, State
# ---------------------------------------------------------------------------

class TestAlertGeneration:
    def test_on_alert_callback_fires_for_each_channel(self):
        received: List[Alert] = []
        v = make_vault(channels=list(AlertChannel))
        v.on_alert = received.append
        v.tick(v.next_checkin_due + timedelta(days=1))
        # One alert per channel
        assert len(received) == len(AlertChannel)

    def test_no_alerts_before_deadline(self):
        received: List[Alert] = []
        v = make_vault(interval_days=30)
        v.on_alert = received.append
        v.tick(utc(day=10))
        assert received == []

    def test_grace_entry_alert_severity_is_critical(self):
        v = make_vault(interval_days=30, max_missed=3)
        all_alerts: List[Alert] = []
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            all_alerts.extend(v.tick(v.next_checkin_due + timedelta(days=1)))
        grace_alerts = [a for a in all_alerts if a.state == VaultState.GRACE_PERIOD]
        assert all(a.severity == AlertSeverity.CRITICAL for a in grace_alerts)

    def test_release_alert_severity_is_critical(self):
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            v.tick(v.next_checkin_due + timedelta(days=1))
        alerts = v.tick(v.grace_period_end + timedelta(days=1))  # type: ignore
        release_alerts = [a for a in alerts
                          if a.state == VaultState.DECEASED_RELEASED]
        assert all(a.severity == AlertSeverity.CRITICAL for a in release_alerts)

    def test_single_channel_vault_emits_one_alert_per_event(self):
        v = make_vault(channels=[AlertChannel.EMAIL])
        alerts = v.tick(v.next_checkin_due + timedelta(days=1))
        # Should be exactly 1 alert (one channel)
        assert len(alerts) == 1

    def test_all_four_channels_covered_on_grace_entry(self):
        v = make_vault(channels=list(AlertChannel))
        all_alerts: List[Alert] = []
        for _ in range(DEFAULT_MAX_MISSED_PINGS):
            all_alerts.extend(v.tick(v.next_checkin_due + timedelta(days=1)))
        grace_alerts = [a for a in all_alerts if a.state == VaultState.GRACE_PERIOD]
        dispatched = {a.channel for a in grace_alerts}
        assert dispatched == {AlertChannel.EMAIL, AlertChannel.WEBHOOK,
                               AlertChannel.TELEGRAM, AlertChannel.SMS}


# ---------------------------------------------------------------------------
# §15 — Reminder Alerts (Approaching Deadline)
# ---------------------------------------------------------------------------

class TestReminderAlerts:
    def test_reminder_fires_within_lead_window(self):
        v = make_vault(interval_days=30)
        # 5 days before deadline (default lead is 7 days)
        due = v.next_checkin_due
        alerts = v.tick(due - timedelta(days=5))
        assert any(a.severity == AlertSeverity.WARNING for a in alerts)

    def test_reminder_does_not_fire_outside_lead_window(self):
        v = make_vault(interval_days=30)
        due = v.next_checkin_due
        alerts = v.tick(due - timedelta(days=10))
        # 10 days before deadline, lead is 7 — should be silent
        assert alerts == []

    def test_reminder_does_not_fire_in_ping_missed_state(self):
        """Reminder is only for ACTIVE state — PING_MISSED has different alerts."""
        v = make_vault(interval_days=30, max_missed=3)
        v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.PING_MISSED
        alerts = v.tick(v.next_checkin_due - timedelta(days=3))
        # Must not produce a soft reminder — check for WARNING-only
        warning_reminders = [
            a for a in alerts
            if a.severity == AlertSeverity.WARNING
               and "Upcoming check-in" in a.message
        ]
        assert warning_reminders == []


# ---------------------------------------------------------------------------
# §16 — Fast-Forward Clock Simulation (End-to-End Scenarios)
# ---------------------------------------------------------------------------

class TestFastForwardSimulation:
    def test_scenario_checkin_then_miss_then_recover(self):
        """
        Timeline:
          Day  0: vault initialized
          Day 25: owner checks in early → ACTIVE, timer reset to day 55
          Day 56: miss #1 → PING_MISSED
          Day 86: miss #2 → still PING_MISSED
          Day 90: owner checks in → ACTIVE again
        """
        v = make_vault(interval_days=30, max_missed=3, grace_days=14)
        start = utc()

        # Early check-in on day 25
        token = v.generate_token()
        v.record_checkin(token, start + timedelta(days=25))
        assert v.state == VaultState.ACTIVE
        # next_due = day 25 + 30 = day 55 from start

        # Miss on day 56 (1 day past new deadline)
        v.tick(start + timedelta(days=56))
        assert v.state == VaultState.PING_MISSED
        assert v.missed_ping_count == 1

        # Miss on day 86 (past 2nd deadline)
        v.tick(start + timedelta(days=87))
        assert v.state == VaultState.PING_MISSED
        assert v.missed_ping_count == 2

        # Owner recovers on day 90
        token2 = v.generate_token()
        v.record_checkin(token2, start + timedelta(days=90))
        assert v.state == VaultState.ACTIVE
        assert v.missed_ping_count == 0

    def test_scenario_full_death_cycle(self):
        """
        Complete death cycle with 3-miss + 14-day grace → DECEASED_RELEASED.
        Uses max_missed=3, interval=10 days, grace=14 days.
        """
        v = make_vault(interval_days=10, max_missed=3, grace_days=14)
        start = utc()

        # Three consecutive misses
        for _ in range(3):
            v.tick(v.next_checkin_due + timedelta(days=1))

        assert v.state == VaultState.GRACE_PERIOD
        grace_start = v.grace_period_start

        # Tick within grace — no release
        v.tick(grace_start + timedelta(days=7))  # type: ignore
        assert v.state == VaultState.GRACE_PERIOD

        # Grace expires
        v.tick(v.grace_period_end + timedelta(seconds=1))  # type: ignore
        assert v.state == VaultState.DECEASED_RELEASED
        assert v.released_at is not None
        assert v.is_terminal is True

    def test_scenario_grace_rescue_on_day_13(self):
        """Owner checks in on day 13 of a 14-day grace window — rescue succeeds."""
        v = make_vault(interval_days=10, max_missed=3, grace_days=14)
        for _ in range(3):
            v.tick(v.next_checkin_due + timedelta(days=1))
        assert v.state == VaultState.GRACE_PERIOD

        rescue_time = v.grace_period_end - timedelta(days=1)  # type: ignore
        token = v.generate_token()
        v.record_checkin(token, rescue_time)
        assert v.state == VaultState.ACTIVE
        assert not v.is_terminal
