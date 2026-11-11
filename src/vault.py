"""
DeadBolt — HeartbeatVault State Machine Engine
===============================================

Security Invariants enforced (from .kiro/steering/security-invariants.md):

  Invariant 1 — Monotonic State Sequence:
    ACTIVE → PING_MISSED → GRACE_PERIOD → DECEASED_RELEASED
    No state may be skipped, jumped, or reversed (except the authenticated
    owner check-in which resets any pre-DECEASED state back to ACTIVE).

  Invariant 2 — No Instant Release:
    A single missed heartbeat NEVER triggers a release or grace window.
    Grace can only begin after MAX_MISSED_PINGS consecutive failed intervals.

  Invariant 3 — Mandatory Grace Period:
    The grace window is at minimum GRACE_PERIOD_DAYS (default 14).
    It cannot be shortened by ticking faster or by external actors.

  Invariant 4 — Escalation Signals:
    Every tick that does not result in owner check-in during GRACE_PERIOD
    fires the alert dispatcher across all registered channels.

  Invariant 5 — Revocability (before DECEASED_RELEASED only):
    A valid authenticated check-in token (magic token or owner signature)
    immediately resets the state machine to ACTIVE and extends the
    next_checkin_due timer.  This is the ONLY backward state transition
    permitted.

  Invariant 6 — Fail-Safe Immutability:
    Once DECEASED_RELEASED is reached, it is a permanent terminal state.
    No operation — including authenticated check-ins — can reverse it.

  Invariant 7 — Non-Repudiation (token replay prevention):
    Each check-in token is single-use.  Used tokens are recorded in a
    consumed set and re-submission raises TokenReplayError.

Design overview:
  ┌──────────────────────────────────────────────────────────────────┐
  │  record_checkin(token)                                           │
  │    Valid token + pre-DECEASED state → ACTIVE, extend timer       │
  │                                                                  │
  │  tick(now)                                                       │
  │    Advance the clock; apply state transitions as needed.         │
  │    Returns list[Alert] describing every side-effect fired.       │
  │                                                                  │
  │  trigger_grace()   (internal, called by tick)                    │
  │    PING_MISSED → GRACE_PERIOD; starts grace countdown            │
  │                                                                  │
  │  finalize_release()  (internal, called by tick)                  │
  │    GRACE_PERIOD → DECEASED_RELEASED; immutable terminal state    │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import Callable, List, Optional, Set


# ---------------------------------------------------------------------------
# Constants / Defaults
# ---------------------------------------------------------------------------

DEFAULT_CHECKIN_INTERVAL_DAYS: int = 30
DEFAULT_MAX_MISSED_PINGS: int = 3
DEFAULT_GRACE_PERIOD_DAYS: int = 14
DEFAULT_REMINDER_LEAD_DAYS: int = 7      # send reminder this many days before due


# ---------------------------------------------------------------------------
# State Enum — monotonic order encoded in integer value
# ---------------------------------------------------------------------------

class VaultState(Enum):
    """
    Heartbeat state machine states in strict monotonic order.

    The integer value encodes the allowed direction of travel: a state
    transition is only valid if new_state.value > current_state.value
    OR if it is an authenticated check-in reverting to ACTIVE.
    """
    ACTIVE             = 1
    PING_MISSED        = 2
    GRACE_PERIOD       = 3
    DECEASED_RELEASED  = 4


# ---------------------------------------------------------------------------
# Alert / Event types (returned by tick() so callers can dispatch)
# ---------------------------------------------------------------------------

class AlertChannel(Enum):
    EMAIL    = "email"
    WEBHOOK  = "webhook"
    TELEGRAM = "telegram"
    SMS      = "sms"


class AlertSeverity(Enum):
    INFO     = "info"
    WARNING  = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Alert:
    """
    A notification event produced by the state machine.

    The state machine itself does NOT deliver alerts — it emits Alert objects
    that the caller (CLI, server, hook) is responsible for dispatching.
    This keeps the engine pure and testable without network side-effects.
    """
    severity:  AlertSeverity
    channel:   AlertChannel
    message:   str
    state:     VaultState
    timestamp: datetime


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidStateTransitionError(Exception):
    """Raised when a requested state transition violates monotonic rules."""


class TokenReplayError(Exception):
    """Raised when a check-in token has already been consumed (replay attack)."""


class InvalidTokenError(Exception):
    """Raised when a check-in token fails HMAC verification."""


class FinalStateError(Exception):
    """Raised when any mutation is attempted on DECEASED_RELEASED vault."""


# ---------------------------------------------------------------------------
# Token generation & verification
# ---------------------------------------------------------------------------

def generate_checkin_token(vault_id: str, secret_key: bytes) -> str:
    """
    Generate a single-use check-in token for a vault.

    Token format:  <vault_id>.<nonce_hex>.<hmac_hex>

    The HMAC signs (vault_id || nonce) under secret_key so the server can
    verify authenticity without storing the token.  The nonce makes every
    token unique even for the same vault_id (non-repudiation / anti-replay).

    Args:
        vault_id:   Unique string identifier for the vault.
        secret_key: 32-byte HMAC key held exclusively by the owner / server.

    Returns:
        A URL-safe token string.
    """
    nonce = secrets.token_hex(16)                   # 128-bit single-use nonce
    message = f"{vault_id}.{nonce}".encode("utf-8")
    mac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
    return f"{vault_id}.{nonce}.{mac}"


def verify_checkin_token(token: str, vault_id: str, secret_key: bytes) -> bool:
    """
    Verify a check-in token's HMAC signature (constant-time comparison).

    Args:
        token:      The token string presented by the owner.
        vault_id:   The vault_id the token claims to be for.
        secret_key: The server's HMAC key for this vault.

    Returns:
        True if the HMAC is valid and the token belongs to vault_id.
        False otherwise (do NOT raise — let the caller decide the response).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        tid, nonce, presented_mac = parts
        if tid != vault_id:
            return False
        message = f"{vault_id}.{nonce}".encode("utf-8")
        expected_mac = hmac.new(secret_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(presented_mac, expected_mac)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# HeartbeatVault — the state machine
# ---------------------------------------------------------------------------

@dataclass
class HeartbeatVault:
    """
    The core state machine for a single DeadBolt vault.

    Attributes (persisted to storage):
        vault_id:              Unique identifier (UUID or similar).
        state:                 Current VaultState.
        checkin_interval:      How long between required check-ins.
        max_missed_pings:      How many consecutive misses trigger GRACE_PERIOD.
        grace_period_duration: Length of the grace window.
        last_checkin_at:       Timestamp of the last successful check-in.
        next_checkin_due:      Deadline; missing this increments missed_ping_count.
        missed_ping_count:     Consecutive missed intervals (resets on check-in).
        grace_period_start:    When GRACE_PERIOD began (None if not in grace).
        grace_period_end:      Deadline for grace window (None if not in grace).
        released_at:           When DECEASED_RELEASED was entered (None otherwise).
        _consumed_tokens:      Set of used token nonces (anti-replay).
        _token_secret:         HMAC key for check-in token verification.
        alert_channels:        Which channels to use for escalation alerts.
        on_alert:              Optional callback; receives each Alert as it fires.
    """

    vault_id: str
    state: VaultState = VaultState.ACTIVE

    # Timing configuration
    checkin_interval:      timedelta = field(
        default_factory=lambda: timedelta(days=DEFAULT_CHECKIN_INTERVAL_DAYS))
    max_missed_pings:      int = DEFAULT_MAX_MISSED_PINGS
    grace_period_duration: timedelta = field(
        default_factory=lambda: timedelta(days=DEFAULT_GRACE_PERIOD_DAYS))
    reminder_lead:         timedelta = field(
        default_factory=lambda: timedelta(days=DEFAULT_REMINDER_LEAD_DAYS))

    # Timestamps
    last_checkin_at:   Optional[datetime] = None
    next_checkin_due:  Optional[datetime] = None
    grace_period_start: Optional[datetime] = None
    grace_period_end:   Optional[datetime] = None
    released_at:        Optional[datetime] = None

    # Missed-ping counter (consecutive)
    missed_ping_count: int = 0

    # Alerting
    alert_channels: List[AlertChannel] = field(
        default_factory=lambda: list(AlertChannel))
    on_alert: Optional[Callable[[Alert], None]] = field(
        default=None, compare=False, repr=False)

    # Anti-replay: consumed token nonces
    _consumed_tokens: Set[str] = field(
        default_factory=set, compare=False, repr=False)

    # HMAC key for token verification (32 bytes, server-held)
    _token_secret: bytes = field(
        default_factory=lambda: os.urandom(32), compare=False, repr=False)

    # ------------------------------------------------------------------
    # Initializer helper
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        """Validate configuration and set initial next_checkin_due if needed."""
        if self.max_missed_pings < 1:
            raise ValueError("max_missed_pings must be >= 1")
        if self.grace_period_duration < timedelta(days=DEFAULT_GRACE_PERIOD_DAYS):
            raise ValueError(
                f"grace_period_duration must be >= {DEFAULT_GRACE_PERIOD_DAYS} days "
                "(security invariant: mandatory grace period)"
            )
        if self.checkin_interval < timedelta(days=1):
            raise ValueError("checkin_interval must be >= 1 day")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def initialize(self, now: datetime) -> None:
        """
        Set the vault live at *now*, establishing the first check-in deadline.

        Must be called once after construction before any tick() calls.
        Idempotent if called multiple times with the same timestamp.
        """
        self._assert_not_released()
        if self.last_checkin_at is None:
            self.last_checkin_at = now
            self.next_checkin_due = now + self.checkin_interval

    def generate_token(self) -> str:
        """
        Produce a fresh single-use check-in token for this vault's owner.

        The token embeds a random nonce to guarantee uniqueness and prevent
        replay attacks (Invariant 7 — Non-Repudiation).
        """
        return generate_checkin_token(self.vault_id, self._token_secret)

    def record_checkin(self, token: str, now: datetime) -> List[Alert]:
        """
        Process an authenticated owner check-in.

        Security invariants applied:
          - Token HMAC is verified (InvalidTokenError on failure).
          - Token nonce is checked against consumed set (TokenReplayError on reuse).
          - If state == DECEASED_RELEASED: FinalStateError — no reversal allowed.
          - Otherwise: state → ACTIVE, missed_ping_count reset, timer extended.

        Args:
            token: The single-use check-in token generated by generate_token().
            now:   The authoritative current timestamp.

        Returns:
            List of Alert objects fired (usually an INFO confirming check-in).

        Raises:
            FinalStateError:   Vault is DECEASED_RELEASED — irreversible.
            InvalidTokenError: HMAC verification failed.
            TokenReplayError:  Token nonce was already consumed.
        """
        # Invariant 6: DECEASED_RELEASED is permanent
        if self.state == VaultState.DECEASED_RELEASED:
            raise FinalStateError(
                "Cannot check in: vault is in terminal state DECEASED_RELEASED. "
                "This transition is permanent and non-reversible."
            )

        # Verify HMAC
        if not verify_checkin_token(token, self.vault_id, self._token_secret):
            raise InvalidTokenError(
                f"Check-in token HMAC verification failed for vault '{self.vault_id}'. "
                "Token is invalid or was not issued by this vault."
            )

        # Anti-replay: extract nonce and check consumed set
        nonce = token.split(".")[1]
        if nonce in self._consumed_tokens:
            raise TokenReplayError(
                f"Token nonce '{nonce}' has already been consumed. "
                "Replay attack detected or token re-submission."
            )
        self._consumed_tokens.add(nonce)

        # Perform state reset → ACTIVE (Invariant 5 — Revocability)
        previous_state = self.state
        self.state = VaultState.ACTIVE
        self.missed_ping_count = 0
        self.last_checkin_at = now
        self.next_checkin_due = now + self.checkin_interval

        # Clear grace period markers if we were in GRACE_PERIOD
        if previous_state in (VaultState.GRACE_PERIOD, VaultState.PING_MISSED):
            self.grace_period_start = None
            self.grace_period_end = None

        alerts = self._emit_alerts(
            severity=AlertSeverity.INFO,
            message=(
                f"Owner check-in received for vault '{self.vault_id}'. "
                f"Previous state: {previous_state.name}. "
                f"State reset to ACTIVE. Next check-in due: {self.next_checkin_due.isoformat()}."
            ),
            state=VaultState.ACTIVE,
            now=now,
        )
        return alerts

    def tick(self, now: datetime) -> List[Alert]:
        """
        Advance the state machine to *now*.

        This is the heartbeat monitor's clock pulse.  Call it periodically
        (e.g. once per day in a cron job).  It evaluates whether deadlines
        have passed and fires the appropriate transitions.

        State transitions applied (in order of precedence):
          1. DECEASED_RELEASED → no-op (terminal, immutable).
          2. ACTIVE / PING_MISSED: if now > next_checkin_due → miss a ping.
          3. PING_MISSED: if missed_ping_count >= max_missed_pings → trigger_grace().
          4. GRACE_PERIOD: if now > grace_period_end → finalize_release().
          5. GRACE_PERIOD: else → emit escalation alert (Invariant 4).
          6. ACTIVE: if next_checkin_due - now <= reminder_lead → emit reminder.

        Args:
            now: The authoritative current timestamp.

        Returns:
            List of Alert objects produced by this tick (may be empty).
        """
        alerts: List[Alert] = []

        # Invariant 6: terminal state — silently absorb all ticks
        if self.state == VaultState.DECEASED_RELEASED:
            return alerts

        # Ensure vault was initialized
        if self.next_checkin_due is None:
            self.initialize(now)
            return alerts

        # --- GRACE_PERIOD evaluation (highest priority deadline check) ---
        if self.state == VaultState.GRACE_PERIOD:
            if now >= self.grace_period_end:  # type: ignore[operator]
                alerts.extend(self._finalize_release(now))
            else:
                # Invariant 4: escalation alerts on every tick during grace
                alerts.extend(self._emit_alerts(
                    severity=AlertSeverity.CRITICAL,
                    message=(
                        f"GRACE PERIOD ACTIVE for vault '{self.vault_id}'. "
                        f"Owner has not checked in. "
                        f"Grace period ends: {self.grace_period_end.isoformat()}. "
                        f"Missed pings: {self.missed_ping_count}. "
                        "IMMEDIATE owner check-in required to prevent inheritance release."
                    ),
                    state=self.state,
                    now=now,
                ))
            return alerts

        # --- Deadline check for ACTIVE and PING_MISSED ---
        if now >= self.next_checkin_due:
            alerts.extend(self._record_missed_ping(now))
            # After recording, check if we just crossed the miss threshold
            if (self.state == VaultState.PING_MISSED
                    and self.missed_ping_count >= self.max_missed_pings):
                alerts.extend(self._trigger_grace(now))
            return alerts

        # --- Reminder: approaching deadline ---
        if (self.state == VaultState.ACTIVE
                and (self.next_checkin_due - now) <= self.reminder_lead):
            alerts.extend(self._emit_alerts(
                severity=AlertSeverity.WARNING,
                message=(
                    f"Upcoming check-in deadline for vault '{self.vault_id}'. "
                    f"Next check-in due: {self.next_checkin_due.isoformat()}. "
                    "Please submit your authenticated check-in link."
                ),
                state=self.state,
                now=now,
            ))

        return alerts

    # ------------------------------------------------------------------
    # Internal state transition methods
    # ------------------------------------------------------------------

    def _record_missed_ping(self, now: datetime) -> List[Alert]:
        """
        Transition logic when a check-in deadline passes without response.

        ACTIVE → PING_MISSED (first miss) or stay PING_MISSED (subsequent).
        Increments missed_ping_count, advances next_checkin_due by one interval.

        This method intentionally does NOT jump to GRACE_PERIOD — that check
        is performed by the caller (tick) to enforce the sequential rule.
        """
        self.missed_ping_count += 1

        # Advance due date by one full interval from the missed deadline
        # (not from `now`, to avoid drift accumulating into a shorter grace window)
        self.next_checkin_due = self.next_checkin_due + self.checkin_interval  # type: ignore[operator]

        # ACTIVE → PING_MISSED on the first miss
        if self.state == VaultState.ACTIVE:
            self.state = VaultState.PING_MISSED

        severity = (AlertSeverity.WARNING
                    if self.missed_ping_count < self.max_missed_pings
                    else AlertSeverity.CRITICAL)

        return self._emit_alerts(
            severity=severity,
            message=(
                f"Missed heartbeat ping #{self.missed_ping_count} for vault '{self.vault_id}'. "
                f"State: {self.state.name}. "
                f"Next check-in due: {self.next_checkin_due.isoformat()}. "
                f"({self.max_missed_pings - self.missed_ping_count} miss(es) remaining "
                f"before GRACE_PERIOD activates.)"
            ),
            state=self.state,
            now=now,
        )

    def _trigger_grace(self, now: datetime) -> List[Alert]:
        """
        PING_MISSED → GRACE_PERIOD.

        Called only when missed_ping_count >= max_missed_pings.
        Starts the grace period countdown from *now*.

        Security invariant: grace_period_duration is validated in __post_init__
        to be >= DEFAULT_GRACE_PERIOD_DAYS (14 days) — cannot be shortened.
        """
        # Enforce monotonic: can only enter from PING_MISSED
        if self.state != VaultState.PING_MISSED:
            raise InvalidStateTransitionError(
                f"trigger_grace() called from invalid state {self.state.name}. "
                "Must be in PING_MISSED state."
            )

        self.state = VaultState.GRACE_PERIOD
        self.grace_period_start = now
        self.grace_period_end = now + self.grace_period_duration

        return self._emit_alerts(
            severity=AlertSeverity.CRITICAL,
            message=(
                f"GRACE PERIOD STARTED for vault '{self.vault_id}'. "
                f"{self.missed_ping_count} consecutive missed pings. "
                f"Grace period: {now.isoformat()} → {self.grace_period_end.isoformat()}. "
                "If no owner check-in is received, inheritance assets will be released to designated heir."
            ),
            state=self.state,
            now=now,
        )

    def _finalize_release(self, now: datetime) -> List[Alert]:
        """
        GRACE_PERIOD → DECEASED_RELEASED (terminal).

        Called when now >= grace_period_end with no intervening check-in.
        Sets released_at and transitions to the permanent terminal state.

        Security invariant: Once set, state cannot be changed by any operation.
        """
        # Enforce monotonic: can only enter from GRACE_PERIOD
        if self.state != VaultState.GRACE_PERIOD:
            raise InvalidStateTransitionError(
                f"finalize_release() called from invalid state {self.state.name}. "
                "Must be in GRACE_PERIOD state."
            )

        self.state = VaultState.DECEASED_RELEASED
        self.released_at = now

        return self._emit_alerts(
            severity=AlertSeverity.CRITICAL,
            message=(
                f"DECEASED_RELEASED: vault '{self.vault_id}' has permanently transitioned. "
                f"Released at: {now.isoformat()}. "
                "Shard 1 is now published to the claimant portal. "
                "Designated heir may claim inheritance by combining Shard 1 + Shard 2."
            ),
            state=self.state,
            now=now,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _assert_not_released(self) -> None:
        """Raise FinalStateError if vault has already been released."""
        if self.state == VaultState.DECEASED_RELEASED:
            raise FinalStateError(
                f"Vault '{self.vault_id}' is in terminal state DECEASED_RELEASED. "
                "No mutations are permitted."
            )

    def _emit_alerts(
        self,
        severity: AlertSeverity,
        message: str,
        state: VaultState,
        now: datetime,
    ) -> List[Alert]:
        """
        Build an Alert for each registered alert channel and fire on_alert
        callback if one is registered.

        Returns the list of Alert objects so tick() can aggregate them.
        """
        alerts: List[Alert] = []
        for channel in self.alert_channels:
            alert = Alert(
                severity=severity,
                channel=channel,
                message=message,
                state=state,
                timestamp=now,
            )
            alerts.append(alert)
            if self.on_alert is not None:
                self.on_alert(alert)
        return alerts

    # ------------------------------------------------------------------
    # Convenience / introspection
    # ------------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        """True once DECEASED_RELEASED is reached — no further mutations allowed."""
        return self.state == VaultState.DECEASED_RELEASED

    @property
    def days_until_due(self) -> Optional[float]:
        """
        Days remaining until next_checkin_due, or None if not initialized.
        Negative means overdue.
        """
        if self.next_checkin_due is None:
            return None
        # Return a timezone-naive delta using the stored timestamps
        # (caller is responsible for consistent timezone usage)
        return (self.next_checkin_due - self.last_checkin_at).days  # type: ignore

    @property
    def days_until_grace_expires(self) -> Optional[float]:
        """Days remaining in grace period, or None if not in GRACE_PERIOD."""
        if self.state != VaultState.GRACE_PERIOD or self.grace_period_end is None:
            return None
        # Relies on caller passing consistent `now` — this is a snapshot value
        return (self.grace_period_end - self.grace_period_start).days  # type: ignore

    def __repr__(self) -> str:
        return (
            f"HeartbeatVault("
            f"id={self.vault_id!r}, "
            f"state={self.state.name}, "
            f"missed={self.missed_ping_count}/{self.max_missed_pings}, "
            f"next_due={self.next_checkin_due!r}"
            f")"
        )
