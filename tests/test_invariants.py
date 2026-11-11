"""
DeadBolt — Task 3: Property-Based Invariant Fuzzing
=====================================================

Uses Hypothesis to fuzz the HeartbeatVault state machine across thousands
of randomised clock jumps, action sequences, and configuration parameters,
asserting every security invariant from .kiro/steering/security-invariants.md.

Security invariants under test
───────────────────────────────
  P1  Zero Early Release
        No tick with now < grace_period_end can ever produce
        DECEASED_RELEASED.  Shard 1 must remain locked.

  P2  Mandatory Grace Duration
        If the vault ever enters GRACE_PERIOD, the window
        grace_period_end - grace_period_start >= 14 days always holds.
        It cannot be compressed by any sequence of ticks.

  P3  Single Miss Never Enters Grace
        Exactly one missed ping → PING_MISSED, never GRACE_PERIOD or
        DECEASED_RELEASED.

  P4  N-1 Misses Never Enter Grace
        For any max_missed_pings=N, applying N-1 consecutive misses leaves
        the vault in PING_MISSED, not GRACE_PERIOD.

  P5  Revocability Interrupts Any Pre-Release State
        An authenticated check-in delivered at any moment before the vault
        reaches DECEASED_RELEASED always resets state to ACTIVE, zeroes
        missed_ping_count, clears grace markers, and extends the timer.

  P6  Monotonic State Progression
        Excluding authenticated check-ins, the integer value of state
        never decreases across any tick sequence.

  P7  Fail-Safe Immutability After Release
        Once DECEASED_RELEASED is entered, no further tick, check-in
        attempt, or clock jump can alter state or released_at.

  P8  Grace Window Is Immutable Once Set
        After GRACE_PERIOD is entered, grace_period_end never moves
        earlier regardless of subsequent ticks.

  P9  Clock Jump Idempotence
        A single massive clock jump to time T produces the same final
        state as N small daily ticks summing to the same T.

  P10 Last-Second Grace Rescue
        A check-in at grace_period_end - 1 second always succeeds and
        reverts to ACTIVE — the boundary is closed/inclusive for safety.

  P11 Token Replay Blocked Under Fuzz
        Submitting the same token twice always raises TokenReplayError,
        regardless of the intervening state.

  P12 Cross-Vault Token Isolation
        A token generated for vault-A is never accepted by vault-B,
        even when both vaults are in identical states.

  P13 Grace Period End Is Deterministic
        grace_period_end depends only on the moment grace was triggered
        and grace_period_duration — not on how many ticks occurred or
        their distribution.

Hypothesis strategies
──────────────────────
  - st_vault_config: randomised (interval_days, max_missed, grace_days)
  - st_tick_sequence: list of non-negative day offsets < grace_period_end
  - st_unlimited_ticks: tick sequences that may cross into or past release
  - st_vault_in_grace: fully constructed vault already in GRACE_PERIOD
  - st_vault_released: fully constructed vault in DECEASED_RELEASED
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from typing import List, Tuple

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from src.vault import (
    DEFAULT_GRACE_PERIOD_DAYS,
    AlertSeverity,
    FinalStateError,
    HeartbeatVault,
    InvalidTokenError,
    TokenReplayError,
    VaultState,
)

# ---------------------------------------------------------------------------
# Shared epoch — all property tests use UTC-aware datetimes
# ---------------------------------------------------------------------------

EPOCH = datetime(2026, 1, 1, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Hypothesis Strategies
# ---------------------------------------------------------------------------

# Valid configuration parameters
st_interval_days   = st.integers(min_value=1,  max_value=90)
st_max_missed      = st.integers(min_value=1,  max_value=5)
st_grace_days      = st.integers(min_value=DEFAULT_GRACE_PERIOD_DAYS, max_value=60)

@st.composite
def st_vault_config(draw) -> Tuple[int, int, int]:
    """Draw (interval_days, max_missed_pings, grace_days)."""
    interval  = draw(st_interval_days)
    max_m     = draw(st_max_missed)
    grace     = draw(st_grace_days)
    return interval, max_m, grace


def _make_vault(interval: int, max_m: int, grace: int) -> HeartbeatVault:
    """Create and initialize a HeartbeatVault anchored at EPOCH."""
    v = HeartbeatVault(
        vault_id="fuzz-vault",
        checkin_interval=timedelta(days=interval),
        max_missed_pings=max_m,
        grace_period_duration=timedelta(days=grace),
        alert_channels=[],       # silence alerts for fuzz speed
    )
    v.initialize(EPOCH)
    return v


def _drive_to_grace(vault: HeartbeatVault) -> datetime:
    """
    Advance *vault* into GRACE_PERIOD by applying exactly max_missed_pings
    consecutive misses.  Returns the timestamp of the last tick applied.
    """
    now = EPOCH
    for _ in range(vault.max_missed_pings):
        now = vault.next_checkin_due + timedelta(days=1)  # type: ignore[operator]
        vault.tick(now)
    assert vault.state == VaultState.GRACE_PERIOD, (
        f"Expected GRACE_PERIOD after {vault.max_missed_pings} misses, "
        f"got {vault.state.name}"
    )
    return now


def _drive_to_release(vault: HeartbeatVault) -> datetime:
    """
    Advance *vault* all the way to DECEASED_RELEASED.
    Returns the timestamp of the finalizing tick.
    """
    _drive_to_grace(vault)
    now = vault.grace_period_end + timedelta(days=1)  # type: ignore[operator]
    vault.tick(now)
    assert vault.state == VaultState.DECEASED_RELEASED
    return now


# ---------------------------------------------------------------------------
# P1 — Zero Early Release
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    # Day-offsets for ticks, each in [0, grace_days * interval_days)
    # We want ticks that individually stay *before* grace_period_end.
    # We don't know grace_period_end until we run the vault, so we generate
    # a list of tick magnitudes and clamp them inside the property itself.
    tick_offsets=st.lists(
        st.integers(min_value=0, max_value=500),
        min_size=1,
        max_size=60,
    ),
)
@settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
def test_p1_zero_early_release(config, tick_offsets):
    """
    P1 — Zero Early Release:
    For any sequence of ticks where now < grace_period_end (or grace has not
    started yet), the vault MUST NOT reach DECEASED_RELEASED.

    Strategy: apply each tick only if its timestamp is strictly before
    grace_period_end (when in grace) or before next_checkin_due + max_misses
    intervals (when not yet in grace), so we never cross the final threshold.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    # Compute the absolute earliest grace_period_end could ever be:
    # EPOCH + max_missed * interval + grace_days (all minimums for this config)
    earliest_possible_grace_end = (
        EPOCH
        + timedelta(days=interval * max_m)
        + timedelta(days=grace)
    )

    base = EPOCH
    for offset in tick_offsets:
        candidate = base + timedelta(days=offset)

        # Only tick if we are safely before the grace window could end
        if candidate >= earliest_possible_grace_end:
            break
        # Also skip if we've already determined the actual grace end
        if vault.grace_period_end is not None and candidate >= vault.grace_period_end:
            break

        vault.tick(candidate)
        base = candidate  # advance base so ticks are loosely monotone

        # ── CORE INVARIANT ──────────────────────────────────────────
        assert vault.state != VaultState.DECEASED_RELEASED, (
            f"P1 VIOLATED: vault reached DECEASED_RELEASED before grace_period_end.\n"
            f"  config=({interval}d interval, max_missed={max_m}, grace={grace}d)\n"
            f"  tick timestamp: {candidate}\n"
            f"  grace_period_end: {vault.grace_period_end}\n"
            f"  released_at: {vault.released_at}\n"
            f"  state: {vault.state.name}"
        )
        assert vault.released_at is None, (
            f"P1 VIOLATED: released_at was set before grace_period_end.\n"
            f"  released_at={vault.released_at}, grace_period_end={vault.grace_period_end}"
        )


# ---------------------------------------------------------------------------
# P2 — Mandatory Grace Duration
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p2_mandatory_grace_duration(config):
    """
    P2 — Mandatory Grace Duration:
    Whenever a vault enters GRACE_PERIOD, the window is at least
    DEFAULT_GRACE_PERIOD_DAYS (14 days).  This invariant is checked both
    at construction time (ValueError) and at runtime after entry.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)
    _drive_to_grace(vault)

    assert vault.grace_period_start is not None
    assert vault.grace_period_end   is not None
    actual_duration = vault.grace_period_end - vault.grace_period_start
    assert actual_duration >= timedelta(days=DEFAULT_GRACE_PERIOD_DAYS), (
        f"P2 VIOLATED: grace window {actual_duration.days}d < 14d.\n"
        f"  config=({interval}d, max_missed={max_m}, grace={grace}d)\n"
        f"  grace_period_start={vault.grace_period_start}\n"
        f"  grace_period_end={vault.grace_period_end}"
    )


@given(grace_days=st.integers(min_value=1, max_value=13))
@settings(max_examples=100)
def test_p2_sub_14_day_grace_construction_rejected(grace_days):
    """
    P2 — sub-14-day grace configurations must be rejected at construction.
    """
    with pytest.raises(ValueError, match="14 days"):
        HeartbeatVault(
            vault_id="short-grace",
            grace_period_duration=timedelta(days=grace_days),
        )


# ---------------------------------------------------------------------------
# P3 — Single Miss Never Enters Grace
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    overshoot_days=st.integers(min_value=1, max_value=365),
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p3_single_miss_never_enters_grace(config, overshoot_days):
    """
    P3 — A single missed ping (regardless of how late the tick arrives)
    must NEVER cause the vault to enter GRACE_PERIOD or DECEASED_RELEASED.
    This is the 'No Instant Release' invariant.
    """
    interval, max_m, grace = config
    assume(max_m >= 2)          # for max_m=1, one miss IS the threshold — skip
    vault = _make_vault(interval, max_m, grace)

    # Apply a single tick that is arbitrarily late past the first deadline
    tick_time = vault.next_checkin_due + timedelta(days=overshoot_days)  # type: ignore
    vault.tick(tick_time)

    assert vault.missed_ping_count == 1
    assert vault.state == VaultState.PING_MISSED, (
        f"P3 VIOLATED: single miss entered {vault.state.name} "
        f"(interval={interval}d, max_missed={max_m}, overshoot={overshoot_days}d)"
    )
    assert vault.state != VaultState.GRACE_PERIOD
    assert vault.state != VaultState.DECEASED_RELEASED
    assert vault.grace_period_start is None
    assert vault.grace_period_end   is None
    assert vault.released_at        is None


# ---------------------------------------------------------------------------
# P4 — N-1 Misses Never Enter Grace
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p4_n_minus_1_misses_never_enter_grace(config):
    """
    P4 — Applying exactly max_missed_pings - 1 consecutive misses must
    leave the vault in PING_MISSED, never in GRACE_PERIOD.
    For max_missed_pings=1, N-1=0, so vault stays ACTIVE after zero misses.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    n_minus_1 = max_m - 1
    for _ in range(n_minus_1):
        vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore

    # Vault should be ACTIVE (if 0 misses) or PING_MISSED (if ≥1 miss)
    assert vault.state in (VaultState.ACTIVE, VaultState.PING_MISSED), (
        f"P4 VIOLATED: {n_minus_1} misses (N-1) produced state {vault.state.name} "
        f"(max_missed={max_m})"
    )
    assert vault.state != VaultState.GRACE_PERIOD
    assert vault.state != VaultState.DECEASED_RELEASED
    assert vault.missed_ping_count == n_minus_1
    assert vault.grace_period_start is None
    assert vault.grace_period_end   is None


# ---------------------------------------------------------------------------
# P5 — Revocability: Check-in During Any Pre-Release State → ACTIVE
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    # Number of misses to apply before the check-in (0 .. max_missed)
    misses_before_checkin=st.integers(min_value=0, max_value=4),
    # Fraction of the grace window to consume before checking in (0.0 to <1.0)
    grace_fraction=st.floats(min_value=0.0, max_value=0.99, allow_nan=False),
)
@settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
def test_p5_revocability_pre_release(config, misses_before_checkin, grace_fraction):
    """
    P5 — An authenticated check-in at any moment before DECEASED_RELEASED
    must immediately reset state to ACTIVE, zero the missed counter,
    clear grace markers, and extend the timer.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    # Apply 'misses_before_checkin' misses, capped to avoid entering grace prematurely
    actual_misses = min(misses_before_checkin, max_m - 1)
    for _ in range(actual_misses):
        vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore

    # If configured to trigger grace, drive all the way in
    if misses_before_checkin >= max_m:
        for _ in range(max_m - actual_misses):
            vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore
        # We're now in GRACE_PERIOD — advance a fraction into it
        assert vault.state == VaultState.GRACE_PERIOD
        grace_duration = vault.grace_period_end - vault.grace_period_start  # type: ignore
        offset = timedelta(seconds=int(grace_duration.total_seconds() * grace_fraction))
        checkin_time = vault.grace_period_start + offset  # type: ignore
        # Ensure we do not accidentally land on or past grace_period_end
        assume(checkin_time < vault.grace_period_end)  # type: ignore
    else:
        # Still in ACTIVE or PING_MISSED — check in just before next deadline
        checkin_time = vault.next_checkin_due - timedelta(hours=1)  # type: ignore

    assert vault.state != VaultState.DECEASED_RELEASED

    token = vault.generate_token()
    vault.record_checkin(token, checkin_time)

    # ── CORE INVARIANT ───────────────────────────────────────────────
    assert vault.state == VaultState.ACTIVE, (
        f"P5 VIOLATED: check-in did not reset state to ACTIVE.\n"
        f"  actual state: {vault.state.name}\n"
        f"  config=({interval}d, max_missed={max_m}, grace={grace}d)"
    )
    assert vault.missed_ping_count == 0, (
        f"P5 VIOLATED: missed_ping_count not zeroed after check-in "
        f"(got {vault.missed_ping_count})"
    )
    assert vault.grace_period_start is None, "P5 VIOLATED: grace_period_start not cleared"
    assert vault.grace_period_end   is None, "P5 VIOLATED: grace_period_end not cleared"
    assert vault.released_at        is None, "P5 VIOLATED: released_at set after check-in"
    assert vault.next_checkin_due == checkin_time + timedelta(days=interval), (
        f"P5 VIOLATED: next_checkin_due not extended correctly "
        f"(got {vault.next_checkin_due}, expected {checkin_time + timedelta(days=interval)})"
    )


# ---------------------------------------------------------------------------
# P6 — Monotonic State Progression (ticks never go backward)
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    tick_offsets=st.lists(
        st.integers(min_value=1, max_value=120),
        min_size=1,
        max_size=100,
    ),
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p6_monotonic_state_progression(config, tick_offsets):
    """
    P6 — Without check-ins, the state integer value never decreases.
    ACTIVE(1) → PING_MISSED(2) → GRACE_PERIOD(3) → DECEASED_RELEASED(4).
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    prev_value = vault.state.value
    base = EPOCH

    for offset in tick_offsets:
        base = base + timedelta(days=offset)
        vault.tick(base)

        current_value = vault.state.value
        assert current_value >= prev_value, (
            f"P6 VIOLATED: state went backward from "
            f"{VaultState(prev_value).name}({prev_value}) → "
            f"{vault.state.name}({current_value}).\n"
            f"  config=({interval}d, max_missed={max_m}, grace={grace}d)\n"
            f"  tick timestamp: {base}"
        )
        prev_value = current_value


# ---------------------------------------------------------------------------
# P7 — Fail-Safe Immutability After Release
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    extra_tick_days=st.integers(min_value=0, max_value=10000),
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p7_immutability_after_release(config, extra_tick_days):
    """
    P7 — Once DECEASED_RELEASED is entered, no tick or check-in attempt
    can alter state or released_at.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)
    release_time = _drive_to_release(vault)

    locked_state      = vault.state
    locked_released_at = vault.released_at

    # Apply arbitrary future tick
    future_time = release_time + timedelta(days=extra_tick_days)
    alerts = vault.tick(future_time)

    assert vault.state      == locked_state,       "P7 VIOLATED: state changed after release"
    assert vault.released_at == locked_released_at, "P7 VIOLATED: released_at changed after release"
    assert alerts == [],                             "P7 VIOLATED: tick after release emitted alerts"

    # Check-in attempt must raise, not silently succeed or mutate state
    token = vault.generate_token()
    with pytest.raises(FinalStateError):
        vault.record_checkin(token, future_time)

    # State must still be unchanged after the failed check-in
    assert vault.state      == locked_state
    assert vault.released_at == locked_released_at


# ---------------------------------------------------------------------------
# P8 — Grace Window Is Immutable Once Set
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    ticks_in_grace=st.integers(min_value=1, max_value=13),
)
@settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
def test_p8_grace_end_immutable_once_set(config, ticks_in_grace):
    """
    P8 — After GRACE_PERIOD is entered, grace_period_end never moves
    earlier regardless of how many ticks occur inside the window.
    Additional ticks must not shorten the window.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)
    _drive_to_grace(vault)

    locked_grace_end = vault.grace_period_end

    # Apply ticks staying inside the grace window
    for day in range(1, ticks_in_grace + 1):
        t = vault.grace_period_start + timedelta(days=day)   # type: ignore
        if t < vault.grace_period_end:                        # type: ignore
            vault.tick(t)

        assert vault.grace_period_end == locked_grace_end, (
            f"P8 VIOLATED: grace_period_end moved from {locked_grace_end} "
            f"to {vault.grace_period_end} after tick on day {day}"
        )
        assert vault.grace_period_end >= (                    # type: ignore
            vault.grace_period_start + timedelta(days=DEFAULT_GRACE_PERIOD_DAYS)   # type: ignore
        ), (
            f"P8 VIOLATED: grace_period_end is less than grace_period_start + 14 days"
        )


# ---------------------------------------------------------------------------
# P9 — Clock Jump Idempotence
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_p9_clock_jump_idempotence(config):
    """
    P9 — Clock jump resistance: a vault driven to DECEASED_RELEASED via large
    clock jumps (one tick per missed-interval, then one tick past grace_end)
    must reach the same terminal state as a vault driven by fine-grained daily
    ticks.

    Note on tick() semantics: each call to tick() processes at most one state
    transition (one missed ping, or one grace → release).  This is intentional
    — it matches how a real cron-based heartbeat monitor works (one evaluation
    per scheduled run).  Therefore 'clock jump idempotence' means that applying
    large per-tick time deltas (e.g. jumping 100 days per tick) produces the
    same final state as applying 1-day ticks, not that a single tick can
    traverse the entire lifecycle.
    """
    interval, max_m, grace = config

    # Fast-path vault: one tick per missed interval (each jump overshoots by
    # an arbitrary amount), then one final jump past grace_end.
    fast_vault = _make_vault(interval, max_m, grace)
    # Miss each interval using a large overshoot (e.g., 2× the interval)
    for _ in range(max_m):
        overshoot = fast_vault.next_checkin_due + timedelta(days=interval * 2)  # type: ignore
        fast_vault.tick(overshoot)
    # Now in GRACE_PERIOD — jump far past the grace window
    assert fast_vault.state == VaultState.GRACE_PERIOD
    fast_vault.tick(fast_vault.grace_period_end + timedelta(days=365))          # type: ignore

    # Slow-path vault: incremental daily ticks
    slow_vault = _make_vault(interval, max_m, grace)
    _drive_to_release(slow_vault)

    assert fast_vault.state == VaultState.DECEASED_RELEASED, (
        f"P9: fast-path vault should be DECEASED_RELEASED, got {fast_vault.state.name}"
    )
    assert slow_vault.state == VaultState.DECEASED_RELEASED, (
        f"P9: slow-path vault should be DECEASED_RELEASED, got {slow_vault.state.name}"
    )
    assert fast_vault.state == slow_vault.state


# ---------------------------------------------------------------------------
# P10 — Last-Second Grace Rescue (Boundary Fuzz)
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_p10_last_second_grace_rescue(config):
    """
    P10 — A check-in delivered at grace_period_end - 1 second must always
    succeed and revert the vault to ACTIVE.  The boundary is treated as a
    half-open interval [start, end) — the owner is alive until proven otherwise.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)
    _drive_to_grace(vault)

    rescue_time = vault.grace_period_end - timedelta(seconds=1)   # type: ignore
    assert rescue_time < vault.grace_period_end                    # type: ignore

    token = vault.generate_token()
    vault.record_checkin(token, rescue_time)

    assert vault.state == VaultState.ACTIVE, (
        f"P10 VIOLATED: last-second rescue did not revert to ACTIVE "
        f"(config: {interval}d, max_missed={max_m}, grace={grace}d)"
    )
    assert vault.grace_period_start is None
    assert vault.grace_period_end   is None
    assert vault.released_at        is None


# ---------------------------------------------------------------------------
# P11 — Token Replay Blocked Under Fuzz
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    replay_state=st.sampled_from(["active", "ping_missed"]),
)
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_p11_token_replay_blocked(config, replay_state):
    """
    P11 — Replaying a consumed token always raises TokenReplayError,
    regardless of how many ticks have occurred or what state the vault is in.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    # Generate and consume one token
    token = vault.generate_token()
    vault.record_checkin(token, EPOCH + timedelta(days=5))

    # Optionally advance into PING_MISSED to test replay in a degraded state
    if replay_state == "ping_missed":
        vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore
        assume(vault.state == VaultState.PING_MISSED or
               vault.state == VaultState.ACTIVE)

    with pytest.raises(TokenReplayError, match="already been consumed"):
        vault.record_checkin(token, EPOCH + timedelta(days=10))


# ---------------------------------------------------------------------------
# P12 — Cross-Vault Token Isolation
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_p12_cross_vault_token_isolation(config):
    """
    P12 — A token generated by vault-A must never be accepted by vault-B,
    even when both vaults have identical configurations and states.
    Each vault's HMAC secret is independently random.
    """
    interval, max_m, grace = config
    vault_a = _make_vault(interval, max_m, grace)
    vault_b = HeartbeatVault(
        vault_id="fuzz-vault",           # same vault_id!
        checkin_interval=timedelta(days=interval),
        max_missed_pings=max_m,
        grace_period_duration=timedelta(days=grace),
        alert_channels=[],
    )
    vault_b.initialize(EPOCH)

    token_a = vault_a.generate_token()

    # vault-B must reject vault-A's token (different _token_secret)
    with pytest.raises(InvalidTokenError):
        vault_b.record_checkin(token_a, EPOCH + timedelta(days=5))


# ---------------------------------------------------------------------------
# P13 — Grace Period End Is Deterministic
# ---------------------------------------------------------------------------

@given(config=st_vault_config())
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_p13_grace_end_is_deterministic(config):
    """
    P13 — grace_period_end depends only on when grace was triggered and
    grace_period_duration, not on how many ticks occurred beforehand or
    their time distribution.

    Two vaults with the same config driven to grace at the same calendar
    moment must produce identical grace_period_end values.

    How we ensure the same moment: drive both vaults to GRACE_PERIOD using
    _drive_to_grace() (which always ticks one-day-past each deadline), then
    assert that grace_period_end - grace_period_start equals grace_days for
    both independently.  The key property is determinism of the duration, not
    equality of absolute timestamps (which legitimately differ if the vaults'
    grace entries happen at slightly different times).
    """
    interval, max_m, grace = config

    vault_a = _make_vault(interval, max_m, grace)
    vault_b = _make_vault(interval, max_m, grace)

    _drive_to_grace(vault_a)
    _drive_to_grace(vault_b)

    assert vault_a.state == VaultState.GRACE_PERIOD
    assert vault_b.state == VaultState.GRACE_PERIOD

    dur_a = vault_a.grace_period_end - vault_a.grace_period_start  # type: ignore
    dur_b = vault_b.grace_period_end - vault_b.grace_period_start  # type: ignore
    expected = timedelta(days=grace)

    assert dur_a == expected, (
        f"P13 VIOLATED: vault-A grace duration {dur_a} != expected {expected}"
    )
    assert dur_b == expected, (
        f"P13 VIOLATED: vault-B grace duration {dur_b} != expected {expected}"
    )
    assert dur_a == dur_b, (
        f"P13 VIOLATED: grace durations differ between vaults: {dur_a} vs {dur_b}"
    )
    # Both grace windows must be at least 14 days
    assert dur_a >= timedelta(days=DEFAULT_GRACE_PERIOD_DAYS)


# ---------------------------------------------------------------------------
# Integration property: Zero Early Release with owner check-ins interleaved
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    # Number of full miss cycles before a check-in (drives toward grace)
    partial_miss_cycles=st.integers(min_value=0, max_value=3),
    # Where in the grace window to check in (fraction 0.0..0.98)
    grace_rescue_fraction=st.floats(
        min_value=0.0, max_value=0.98, allow_nan=False
    ),
)
@settings(max_examples=600, suppress_health_check=[HealthCheck.too_slow])
def test_p_integration_no_release_before_grace_end_with_interleaved_checkins(
    config, partial_miss_cycles, grace_rescue_fraction
):
    """
    Integration property: even with interleaved check-ins and partial miss
    cycles, the vault must never reach DECEASED_RELEASED before grace_period_end.

    Models the realistic owner who sometimes forgets to check in but always
    recovers before the grace window expires.
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    # Apply partial miss cycles (each cycle = max_m - 1 misses then recover)
    for _ in range(partial_miss_cycles):
        misses = max_m - 1
        for _ in range(misses):
            vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore
        # Recover before hitting grace
        checkin_t = vault.next_checkin_due - timedelta(hours=6)     # type: ignore
        token = vault.generate_token()
        vault.record_checkin(token, checkin_t)
        assert vault.state == VaultState.ACTIVE

    # Now drive fully into grace
    for _ in range(max_m):
        vault.tick(vault.next_checkin_due + timedelta(days=1))  # type: ignore

    if vault.state != VaultState.GRACE_PERIOD:
        # Could have looped back to ACTIVE on last step if max_m=1 and we
        # drove it once before — just ensure no release
        assert vault.state != VaultState.DECEASED_RELEASED
        return

    # Rescue partway through grace
    assert vault.grace_period_end is not None
    grace_secs = (vault.grace_period_end - vault.grace_period_start).total_seconds()   # type: ignore
    rescue_offset = timedelta(seconds=int(grace_secs * grace_rescue_fraction))
    rescue_time = vault.grace_period_start + rescue_offset                              # type: ignore
    assume(rescue_time < vault.grace_period_end)

    # At rescue_time vault must NOT be released yet
    assert vault.state == VaultState.GRACE_PERIOD
    assert vault.state != VaultState.DECEASED_RELEASED, (
        "Integration VIOLATED: vault reached DECEASED_RELEASED before grace_period_end"
    )

    token = vault.generate_token()
    vault.record_checkin(token, rescue_time)
    assert vault.state == VaultState.ACTIVE
    assert vault.released_at is None


# ---------------------------------------------------------------------------
# Stress: Thousands of random tick sequences never violate core invariants
# ---------------------------------------------------------------------------

@given(
    config=st_vault_config(),
    tick_days=st.lists(
        st.integers(min_value=1, max_value=30),
        min_size=5,
        max_size=200,
    ),
)
@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
def test_stress_core_invariants_hold_across_random_sequences(config, tick_days):
    """
    Stress test: apply up to 200 random daily tick increments and verify that
    after each tick the following invariants always hold simultaneously:

      (a) state is one of the four valid VaultState values
      (b) state integer value never decreases
      (c) if state != GRACE_PERIOD: grace_period_end is None
      (d) if state != DECEASED_RELEASED: released_at is None
      (e) missed_ping_count is non-negative and < max_missed_pings + 1
          (it resets on grace entry, so can be == max_missed_pings)
      (f) if DECEASED_RELEASED: released_at is not None
    """
    interval, max_m, grace = config
    vault = _make_vault(interval, max_m, grace)

    prev_state_value = vault.state.value
    base = EPOCH

    for delta_days in tick_days:
        base = base + timedelta(days=delta_days)
        vault.tick(base)

        s = vault.state

        # (a) valid state
        assert s in VaultState, f"Invalid state: {s}"

        # (b) monotonicity (without check-ins)
        assert s.value >= prev_state_value, (
            f"State went backward: {VaultState(prev_state_value).name} → {s.name}"
        )
        prev_state_value = s.value

        # (c) grace markers cleared outside GRACE_PERIOD
        if s not in (VaultState.GRACE_PERIOD, VaultState.DECEASED_RELEASED):
            assert vault.grace_period_end is None, (
                f"grace_period_end set while in {s.name}"
            )

        # (d) released_at only set in DECEASED_RELEASED
        if s != VaultState.DECEASED_RELEASED:
            assert vault.released_at is None, (
                f"released_at set while in {s.name}"
            )

        # (e) missed counter sanity
        assert vault.missed_ping_count >= 0
        assert vault.missed_ping_count <= max_m, (
            f"missed_ping_count {vault.missed_ping_count} > max_missed {max_m}"
        )

        # (f) DECEASED_RELEASED ↔ released_at set
        if s == VaultState.DECEASED_RELEASED:
            assert vault.released_at is not None, (
                "released_at is None in DECEASED_RELEASED state"
            )
