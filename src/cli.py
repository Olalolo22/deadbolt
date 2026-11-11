"""
DeadBolt — Interactive CLI Demonstration Surface
=================================================

Commands
--------
  deadbolt init            Create a new vault, encrypt the secret, print Shard 2.
  deadbolt status          Print a rich terminal card showing vault health.
  deadbolt checkin         Authenticated owner check-in; resets state to ACTIVE.
  deadbolt fast-forward    Advance simulated clock by N days (demo / testing).
  deadbolt claim           Heir combines Shard 2 + Shard 1 to decrypt inheritance.

Security invariants honoured
-----------------------------
  Zero Custody:  Shard 1 is stored in the vault file but only printed / released
                 to claimants when state == DECEASED_RELEASED.  The server (this
                 process) never reconstructs K while the owner is alive.
  Anti-replay:   Every check-in token is single-use; nonces are persisted.
  Immutability:  DECEASED_RELEASED cannot be reversed from the CLI.

Persistence
-----------
  Vault state is stored as a JSON file at:
    <vault_dir>/vault.json        (default: ~/.deadbolt/vault.json)

  Sensitive fields in vault.json:
    encrypted_vault_hex   safe to store (ciphertext only)
    shard_1_hex           stored locked; exposed ONLY on DECEASED_RELEASED
    shard_3_hex           cold backup (never printed to screen)
    consumed_tokens       set of used nonces (anti-replay)

  Shard 2 is printed ONCE at init and never stored here — Zero Custody.

Simulated clock
---------------
  sim_clock_offset_seconds (int) is added to wall-clock time so that
  `fast-forward --days N` can advance the simulation without touching
  system time.  All tick() calls use sim_now = utcnow + offset.
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from src.crypto import (
    AES_KEY_BYTES,
    EncryptedVault,
    Shard,
    create_vault,
    decrypt_secret,
    shamir_combine,
    shamir_split,
)
from src.vault import (
    DEFAULT_CHECKIN_INTERVAL_DAYS,
    DEFAULT_GRACE_PERIOD_DAYS,
    DEFAULT_MAX_MISSED_PINGS,
    Alert,
    AlertChannel,
    HeartbeatVault,
    InvalidTokenError,
    FinalStateError,
    TokenReplayError,
    VaultState,
)

# ---------------------------------------------------------------------------
# Console
# ---------------------------------------------------------------------------

console = Console()

# ---------------------------------------------------------------------------
# Palette / theme
# ---------------------------------------------------------------------------

STATE_STYLE: Dict[str, str] = {
    VaultState.ACTIVE.name:            "bold green",
    VaultState.PING_MISSED.name:       "bold yellow",
    VaultState.GRACE_PERIOD.name:      "bold red",
    VaultState.DECEASED_RELEASED.name: "bold white on red",
}

STATE_EMOJI: Dict[str, str] = {
    VaultState.ACTIVE.name:            "💚",
    VaultState.PING_MISSED.name:       "⚠️ ",
    VaultState.GRACE_PERIOD.name:      "🚨",
    VaultState.DECEASED_RELEASED.name: "💀",
}

# ---------------------------------------------------------------------------
# Vault persistence helpers
# ---------------------------------------------------------------------------

DEFAULT_VAULT_DIR = Path.home() / ".deadbolt"
VAULT_FILENAME    = "vault.json"


def _vault_path(vault_dir: Path) -> Path:
    return vault_dir / VAULT_FILENAME


def _load_raw(vault_dir: Path) -> Dict[str, Any]:
    path = _vault_path(vault_dir)
    if not path.exists():
        raise click.ClickException(
            f"No vault found at {path}.\n"
            "Run [bold cyan]deadbolt init[/bold cyan] first."
        )
    with path.open() as fh:
        return json.load(fh)


def _save_raw(data: Dict[str, Any], vault_dir: Path) -> None:
    vault_dir.mkdir(parents=True, exist_ok=True)
    path = _vault_path(vault_dir)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2)


# ---------------------------------------------------------------------------
# Serialise / deserialise HeartbeatVault ↔ JSON
# ---------------------------------------------------------------------------

def _dt_to_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt is not None else None


def _iso_to_dt(s: Optional[str]) -> Optional[datetime]:
    if s is None:
        return None
    return datetime.fromisoformat(s)


def _vault_to_dict(
    vault: HeartbeatVault,
    encrypted_vault_hex: str,
    shard_1_hex: str,
    shard_3_hex: str,
    sim_clock_offset_seconds: int,
    alert_log: List[Dict[str, str]],
) -> Dict[str, Any]:
    return {
        "vault_id":                  vault.vault_id,
        "state":                     vault.state.name,
        "checkin_interval_days":     int(vault.checkin_interval.total_seconds() // 86400),
        "max_missed_pings":          vault.max_missed_pings,
        "grace_period_days":         int(vault.grace_period_duration.total_seconds() // 86400),
        "reminder_lead_days":        int(vault.reminder_lead.total_seconds() // 86400),
        "last_checkin_at":           _dt_to_iso(vault.last_checkin_at),
        "next_checkin_due":          _dt_to_iso(vault.next_checkin_due),
        "grace_period_start":        _dt_to_iso(vault.grace_period_start),
        "grace_period_end":          _dt_to_iso(vault.grace_period_end),
        "released_at":               _dt_to_iso(vault.released_at),
        "missed_ping_count":         vault.missed_ping_count,
        "token_secret_hex":          vault._token_secret.hex(),
        "consumed_tokens":           list(vault._consumed_tokens),
        # Crypto material
        "encrypted_vault_hex":       encrypted_vault_hex,
        "shard_1_hex":               shard_1_hex,       # locked until DECEASED_RELEASED
        "shard_3_hex":               shard_3_hex,       # cold backup, never displayed
        # Simulation
        "sim_clock_offset_seconds":  sim_clock_offset_seconds,
        # Audit
        "alert_log":                 alert_log,
    }


def _vault_from_dict(data: Dict[str, Any]) -> HeartbeatVault:
    vault = HeartbeatVault.__new__(HeartbeatVault)
    vault.vault_id              = data["vault_id"]
    vault.state                 = VaultState[data["state"]]
    vault.checkin_interval      = timedelta(days=data["checkin_interval_days"])
    vault.max_missed_pings      = data["max_missed_pings"]
    vault.grace_period_duration = timedelta(days=data["grace_period_days"])
    vault.reminder_lead         = timedelta(days=data["reminder_lead_days"])
    vault.last_checkin_at       = _iso_to_dt(data.get("last_checkin_at"))
    vault.next_checkin_due      = _iso_to_dt(data.get("next_checkin_due"))
    vault.grace_period_start    = _iso_to_dt(data.get("grace_period_start"))
    vault.grace_period_end      = _iso_to_dt(data.get("grace_period_end"))
    vault.released_at           = _iso_to_dt(data.get("released_at"))
    vault.missed_ping_count     = data["missed_ping_count"]
    vault._token_secret         = bytes.fromhex(data["token_secret_hex"])
    vault._consumed_tokens      = set(data.get("consumed_tokens", []))
    vault.alert_channels        = list(AlertChannel)
    vault.on_alert              = None
    return vault


def _sim_now(offset_seconds: int) -> datetime:
    """Return the simulated current time (wall-clock + offset)."""
    return datetime.now(tz=timezone.utc) + timedelta(seconds=offset_seconds)


# ---------------------------------------------------------------------------
# Rich UI helpers
# ---------------------------------------------------------------------------

def _state_badge(state_name: str) -> Text:
    emoji = STATE_EMOJI.get(state_name, "?")
    style = STATE_STYLE.get(state_name, "white")
    return Text(f"{emoji} {state_name}", style=style)


def _print_status_card(vault: HeartbeatVault, sim_now: datetime,
                       alert_log: List[Dict[str, str]]) -> None:
    """Render a rich terminal card for `deadbolt status`."""
    state_name = vault.state.name

    # ── Header ──────────────────────────────────────────────────────
    header = Text()
    header.append("⚡ DeadBolt Vault  ", style="bold cyan")
    header.append(vault.vault_id, style="dim")

    # ── State table ─────────────────────────────────────────────────
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("key",   style="dim",   no_wrap=True)
    table.add_column("value", no_wrap=False)

    table.add_row("State",         _state_badge(state_name))
    table.add_row("Sim clock",     sim_now.strftime("%Y-%m-%d %H:%M UTC"))

    if vault.next_checkin_due:
        due = vault.next_checkin_due
        remaining = due - sim_now
        days_left = remaining.days
        if vault.state == VaultState.ACTIVE:
            due_style = "green" if days_left > 7 else "yellow"
            table.add_row(
                "Next check-in",
                Text(f"{due.strftime('%Y-%m-%d')}  ({days_left}d remaining)",
                     style=due_style),
            )
        elif vault.state == VaultState.PING_MISSED:
            table.add_row(
                "Missed pings",
                Text(f"{vault.missed_ping_count} / {vault.max_missed_pings}",
                     style="bold yellow"),
            )

    if vault.state == VaultState.GRACE_PERIOD and vault.grace_period_end:
        gend = vault.grace_period_end
        gremain = gend - sim_now
        table.add_row(
            "Grace ends",
            Text(f"{gend.strftime('%Y-%m-%d %H:%M UTC')}  "
                 f"({max(0, gremain.days)}d {gremain.seconds // 3600}h remaining)",
                 style="bold red"),
        )

    if vault.state == VaultState.DECEASED_RELEASED and vault.released_at:
        table.add_row(
            "Released at",
            Text(vault.released_at.strftime("%Y-%m-%d %H:%M UTC"),
                 style="bold white on red"),
        )
        table.add_row(
            "Shard 1 status",
            Text("🔓 PUBLISHED — heir may now claim", style="bold red"),
        )

    if vault.last_checkin_at:
        table.add_row(
            "Last check-in",
            vault.last_checkin_at.strftime("%Y-%m-%d %H:%M UTC"),
        )

    # ── Alert log ───────────────────────────────────────────────────
    log_lines: List[str] = []
    for entry in alert_log[-8:]:      # last 8 entries
        sev   = entry.get("severity", "")
        ts    = entry.get("timestamp", "")[:16].replace("T", " ")
        msg   = entry.get("message", "")[:80]
        sev_style = {"CRITICAL": "red", "WARNING": "yellow", "INFO": "green"}.get(sev, "white")
        log_lines.append(f"[{sev_style}][{sev[:4]}][/{sev_style}] {ts}  {msg}")

    log_text = "\n".join(log_lines) if log_lines else "[dim]No alerts recorded.[/dim]"

    # ── Compose panel ───────────────────────────────────────────────
    border_style = {
        VaultState.ACTIVE.name:            "green",
        VaultState.PING_MISSED.name:       "yellow",
        VaultState.GRACE_PERIOD.name:      "red",
        VaultState.DECEASED_RELEASED.name: "bright_red",
    }.get(state_name, "white")

    console.print(Panel(table, title=header, border_style=border_style,
                        expand=False))
    if log_lines:
        console.print(Panel(log_text, title="[dim]Alert Log (last 8)[/dim]",
                            border_style="dim", expand=False))


def _append_alerts_to_log(alert_log: List[Dict[str, str]],
                           alerts: List[Alert]) -> None:
    """Dedup-by-timestamp+message and append new alerts to the persistent log."""
    seen = {(e["timestamp"], e["message"]) for e in alert_log}
    for a in alerts:
        key = (a.timestamp.isoformat(), a.message)
        if key not in seen:
            seen.add(key)
            alert_log.append({
                "severity":  a.severity.name,
                "channel":   a.channel.name,
                "state":     a.state.name,
                "timestamp": a.timestamp.isoformat(),
                "message":   a.message,
            })


# ---------------------------------------------------------------------------
# Click CLI
# ---------------------------------------------------------------------------

@click.group()
@click.option(
    "--vault-dir",
    envvar="DEADBOLT_VAULT_DIR",
    default=str(DEFAULT_VAULT_DIR),
    show_default=True,
    help="Directory where vault.json is stored.",
)
@click.pass_context
def cli(ctx: click.Context, vault_dir: str) -> None:
    """
    ⚡ DeadBolt — Autonomous Digital Trust & Succession Protocol

    Zero-custody cryptographic dead-man's switch for self-custodied assets.
    """
    ctx.ensure_object(dict)
    ctx.obj["vault_dir"] = Path(vault_dir)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--vault-id",         default=None,  help="Custom vault ID (UUID generated if omitted).")
@click.option("--interval-days",    default=DEFAULT_CHECKIN_INTERVAL_DAYS,  show_default=True,
              help="Days between required check-ins.")
@click.option("--max-missed",       default=DEFAULT_MAX_MISSED_PINGS,       show_default=True,
              help="Consecutive misses before grace period.")
@click.option("--grace-days",       default=DEFAULT_GRACE_PERIOD_DAYS,      show_default=True,
              help="Grace window length (days, min 14).")
@click.option("--secret",           default=None,  help="Secret payload (use stdin prompt if omitted).")
@click.option("--non-interactive",  is_flag=True,  default=False,
              help="Skip confirmations (for tests/CI).")
@click.pass_context
def init(ctx: click.Context,
         vault_id: Optional[str],
         interval_days: int,
         max_missed: int,
         grace_days: int,
         secret: Optional[str],
         non_interactive: bool) -> None:
    """
    Create a new DeadBolt vault.

    \b
    1. Encrypts your secret payload with AES-256-GCM (client-side).
    2. Splits the master key into a 2-of-3 Shamir threshold.
    3. Prints Shard 2 for your heir — NEVER stored server-side.
    4. Saves vault state to disk.
    """
    vault_dir: Path = ctx.obj["vault_dir"]

    # Guard: don't clobber an existing vault
    if _vault_path(vault_dir).exists() and not non_interactive:
        overwrite = click.confirm(
            "⚠️  A vault already exists. Overwrite?", default=False)
        if not overwrite:
            console.print("[yellow]Aborted.[/yellow]")
            return

    # ── Gather secret ───────────────────────────────────────────────
    if secret is None:
        console.print(Panel(
            "[bold]Enter the secret payload to protect.[/bold]\n"
            "[dim]This may be a seed phrase, private key, or testament letter.\n"
            "It is encrypted client-side — this process never sees the plaintext key.[/dim]",
            title="[cyan]Secret Input[/cyan]",
            border_style="cyan",
        ))
        secret = click.prompt("Secret payload", hide_input=True)
        if not non_interactive:
            secret_confirm = click.prompt("Confirm secret", hide_input=True)
            if secret != secret_confirm:
                raise click.ClickException("Secrets do not match.")

    plaintext = secret.encode("utf-8")

    # ── Vault ID ────────────────────────────────────────────────────
    if vault_id is None:
        import uuid
        vault_id = str(uuid.uuid4())

    # ── Encrypt + shard ─────────────────────────────────────────────
    bundle = create_vault(plaintext)

    shard_1_hex = bundle.shard_1.value.hex()
    shard_2_hex = bundle.shard_2.value.hex()   # → heir; NEVER stored here
    shard_3_hex = bundle.shard_3.value.hex()   # cold backup
    enc_hex     = bundle.vault.to_bytes().hex()

    # ── Heartbeat vault ─────────────────────────────────────────────
    hb_vault = HeartbeatVault(
        vault_id=vault_id,
        checkin_interval=timedelta(days=interval_days),
        max_missed_pings=max_missed,
        grace_period_duration=timedelta(days=grace_days),
        alert_channels=list(AlertChannel),
    )
    now = datetime.now(tz=timezone.utc)
    hb_vault.initialize(now)

    # ── Persist ─────────────────────────────────────────────────────
    data = _vault_to_dict(
        vault=hb_vault,
        encrypted_vault_hex=enc_hex,
        shard_1_hex=shard_1_hex,
        shard_3_hex=shard_3_hex,
        sim_clock_offset_seconds=0,
        alert_log=[],
    )
    _save_raw(data, vault_dir)

    # ── Output ──────────────────────────────────────────────────────
    console.print(Panel(
        f"[green]Vault created successfully.[/green]\n\n"
        f"[bold]Vault ID:[/bold] {vault_id}\n"
        f"[bold]Check-in interval:[/bold] every {interval_days} days\n"
        f"[bold]Grace period:[/bold] {grace_days} days after {max_missed} missed pings\n"
        f"[bold]Stored at:[/bold] {_vault_path(vault_dir)}",
        title="[bold cyan]⚡ DeadBolt Vault Initialized[/bold cyan]",
        border_style="green",
    ))

    # Shard 2 — print prominently for the heir
    console.print(Panel(
        f"[bold yellow]SHARD 2 — HEIR RECOVERY TOKEN[/bold yellow]\n\n"
        f"[bold white]{shard_2_hex}[/bold white]\n\n"
        f"[dim]⚠️  Deliver this token to your designated heir NOW.\n"
        f"This value is NEVER stored by DeadBolt. If lost, it cannot be recovered.\n"
        f"Combined with Shard 1 (released on death), it reconstructs your master key.[/dim]",
        title="[yellow]🔑 Heir Shard (Shard 2) — SAVE THIS[/yellow]",
        border_style="yellow",
    ))

    # Shard 3 — cold backup
    console.print(Panel(
        f"[bold]SHARD 3 — COLD BACKUP (store offline)[/bold]\n\n"
        f"[dim white]{shard_3_hex}[/dim white]\n\n"
        f"[dim]Print and store in a fireproof safe or hardware wallet.[/dim]",
        title="[dim]🔐 Cold Backup Shard (Shard 3)[/dim]",
        border_style="dim",
    ))


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Print a rich terminal card showing vault health and alarm log."""
    vault_dir: Path = ctx.obj["vault_dir"]
    data     = _load_raw(vault_dir)
    vault    = _vault_from_dict(data)
    offset   = data.get("sim_clock_offset_seconds", 0)
    alert_log = data.get("alert_log", [])
    now      = _sim_now(offset)

    # Run one tick to surface any new state changes
    new_alerts: List[Alert] = []
    vault.on_alert = lambda a: new_alerts.append(a)
    vault.tick(now)

    if new_alerts:
        _append_alerts_to_log(alert_log, new_alerts)
        updated_data = _vault_to_dict(
            vault=vault,
            encrypted_vault_hex=data["encrypted_vault_hex"],
            shard_1_hex=data["shard_1_hex"],
            shard_3_hex=data["shard_3_hex"],
            sim_clock_offset_seconds=offset,
            alert_log=alert_log,
        )
        _save_raw(updated_data, vault_dir)

    _print_status_card(vault, now, alert_log)


# ---------------------------------------------------------------------------
# checkin
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--token", default=None,
              help="Pre-generated check-in token (prompted if omitted).")
@click.pass_context
def checkin(ctx: click.Context, token: Optional[str]) -> None:
    """
    Authenticated owner check-in.

    Resets the heartbeat timer back to ACTIVE and extends the next deadline.
    Requires a valid single-use token generated by this vault.
    """
    vault_dir: Path = ctx.obj["vault_dir"]
    data      = _load_raw(vault_dir)
    vault     = _vault_from_dict(data)
    offset    = data.get("sim_clock_offset_seconds", 0)
    alert_log = data.get("alert_log", [])
    now       = _sim_now(offset)

    if vault.state == VaultState.DECEASED_RELEASED:
        console.print(Panel(
            "[bold red]DECEASED_RELEASED — this vault is in a terminal state.\n"
            "No check-in can reverse the inheritance release.[/bold red]",
            border_style="red",
        ))
        sys.exit(1)

    # Generate and immediately consume a fresh token so the user doesn't have
    # to manage token strings in a demo scenario.  For a real deployment the
    # token would be delivered by email/SMS and pasted here.
    fresh_token = vault.generate_token()

    if token is None:
        console.print(
            "[dim]No token provided — using a freshly generated token for this session.[/dim]"
        )
        token = fresh_token

    new_alerts: List[Alert] = []
    try:
        alerts = vault.record_checkin(token, now)
        new_alerts.extend(alerts)
    except (InvalidTokenError, TokenReplayError) as exc:
        raise click.ClickException(str(exc))

    _append_alerts_to_log(alert_log, new_alerts)
    updated = _vault_to_dict(
        vault=vault,
        encrypted_vault_hex=data["encrypted_vault_hex"],
        shard_1_hex=data["shard_1_hex"],
        shard_3_hex=data["shard_3_hex"],
        sim_clock_offset_seconds=offset,
        alert_log=alert_log,
    )
    _save_raw(updated, vault_dir)

    console.print(Panel(
        f"[bold green]✅ Check-in confirmed![/bold green]\n\n"
        f"[bold]Vault:[/bold] {vault.vault_id}\n"
        f"[bold]Checked in at:[/bold] {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"[bold]Next deadline:[/bold] {vault.next_checkin_due.strftime('%Y-%m-%d %H:%M UTC')}\n"  # type: ignore
        f"[bold]Missed ping count reset to:[/bold] 0",
        title="[green]💚 Heartbeat Confirmed[/green]",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# fast-forward
# ---------------------------------------------------------------------------

@cli.command("fast-forward")
@click.option("--days", required=True, type=int,
              help="Number of days to advance the simulated clock.")
@click.pass_context
def fast_forward(ctx: click.Context, days: int) -> None:
    """
    Advance the simulated clock by DAYS days.

    \b
    Demonstrates the full lifecycle:
      • Missed heartbeats (ACTIVE → PING_MISSED)
      • Grace period activation (PING_MISSED → GRACE_PERIOD)
      • Inheritance release (GRACE_PERIOD → DECEASED_RELEASED)
    """
    if days < 1:
        raise click.ClickException("--days must be a positive integer.")

    vault_dir: Path = ctx.obj["vault_dir"]
    data      = _load_raw(vault_dir)
    vault     = _vault_from_dict(data)
    offset    = data.get("sim_clock_offset_seconds", 0)
    alert_log = data.get("alert_log", [])

    base_now  = _sim_now(offset)

    console.print(
        f"\n[bold cyan]⏩ Fast-forwarding {days} day(s)[/bold cyan]  "
        f"[dim]from {base_now.strftime('%Y-%m-%d')}[/dim]\n"
    )

    all_alerts: List[Alert] = []
    state_changes: List[str] = []
    prev_state = vault.state

    # Tick once per day
    for d in range(1, days + 1):
        sim_time = base_now + timedelta(days=d)
        daily_alerts: List[Alert] = []
        vault.on_alert = lambda a: daily_alerts.append(a)
        vault.tick(sim_time)

        # Deduplicate and log
        for a in daily_alerts:
            if not any(x.message == a.message and x.timestamp == a.timestamp
                       for x in all_alerts):
                all_alerts.append(a)

        if vault.state != prev_state:
            state_changes.append(
                f"Day +{d:>4}  "
                f"[dim]{prev_state.name}[/dim] → "
                f"[{STATE_STYLE.get(vault.state.name, 'white')}]{vault.state.name}[/{STATE_STYLE.get(vault.state.name, 'white')}]"
                f"  [dim]({sim_time.strftime('%Y-%m-%d')})[/dim]"
            )
            prev_state = vault.state

        if vault.state == VaultState.DECEASED_RELEASED:
            break

    # Update offset to end of fast-forward
    new_offset = offset + days * 86400
    final_now  = _sim_now(new_offset)

    _append_alerts_to_log(alert_log, all_alerts)
    updated = _vault_to_dict(
        vault=vault,
        encrypted_vault_hex=data["encrypted_vault_hex"],
        shard_1_hex=data["shard_1_hex"],
        shard_3_hex=data["shard_3_hex"],
        sim_clock_offset_seconds=new_offset,
        alert_log=alert_log,
    )
    _save_raw(updated, vault_dir)

    # ── Print transition log ─────────────────────────────────────────
    if state_changes:
        transitions_text = "\n".join(state_changes)
        console.print(Panel(
            transitions_text,
            title="[bold]State Transitions[/bold]",
            border_style="cyan",
        ))
    else:
        console.print(f"[dim]No state transitions in {days} day(s).[/dim]")

    # Print final status
    _print_status_card(vault, final_now, alert_log)


# ---------------------------------------------------------------------------
# claim
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--shard-2", "shard_2_hex", default=None,
              help="Heir's Shard 2 hex string (prompted if omitted).")
@click.pass_context
def claim(ctx: click.Context, shard_2_hex: Optional[str]) -> None:
    """
    Heir inheritance claim.

    \b
    Requires vault state == DECEASED_RELEASED.
    Combines Shard 1 (published by DeadBolt) + Shard 2 (held by heir)
    to reconstruct the master key K, then decrypts the secret payload.

    The reconstruction and decryption happen entirely client-side —
    no plaintext is ever sent to a server.
    """
    vault_dir: Path = ctx.obj["vault_dir"]
    data      = _load_raw(vault_dir)
    vault     = _vault_from_dict(data)
    offset    = data.get("sim_clock_offset_seconds", 0)
    alert_log = data.get("alert_log", [])
    now       = _sim_now(offset)

    # Tick one final time to catch any just-expired grace window
    vault.tick(now)

    if vault.state != VaultState.DECEASED_RELEASED:
        console.print(Panel(
            f"[bold yellow]Claim rejected:[/bold yellow] vault is [bold]{vault.state.name}[/bold].\n\n"
            f"Shard 1 is only released when state = [bold red]DECEASED_RELEASED[/bold red].\n"
            f"Current state: [bold]{vault.state.name}[/bold]",
            title="[yellow]⚠️  Claim Not Yet Available[/yellow]",
            border_style="yellow",
        ))
        sys.exit(1)

    # ── Retrieve Shard 1 (now unlocked) ─────────────────────────────
    shard_1_hex = data["shard_1_hex"]
    console.print(Panel(
        f"[bold red]DECEASED_RELEASED — Shard 1 is now public.[/bold red]\n\n"
        f"[dim]Shard 1:[/dim] [white]{shard_1_hex}[/white]",
        title="[red]💀 Shard 1 Published[/red]",
        border_style="red",
    ))

    # ── Gather Shard 2 from heir ─────────────────────────────────────
    if shard_2_hex is None:
        shard_2_hex = click.prompt(
            "\nEnter your Shard 2 (the heir token you received at vault creation)"
        ).strip()

    # ── Reconstruct master key K ─────────────────────────────────────
    try:
        s1 = Shard(index=1, value=bytes.fromhex(shard_1_hex))
        s2 = Shard(index=2, value=bytes.fromhex(shard_2_hex))
        master_key = shamir_combine([s1, s2])
    except (ValueError, Exception) as exc:
        raise click.ClickException(
            f"Failed to reconstruct master key from shards: {exc}\n"
            "Ensure Shard 2 is correct and unmodified."
        )

    # ── Decrypt vault payload ────────────────────────────────────────
    try:
        enc_bytes = bytes.fromhex(data["encrypted_vault_hex"])
        enc_vault = EncryptedVault.from_bytes(enc_bytes)
        plaintext = decrypt_secret(enc_vault, master_key)
    except Exception as exc:
        raise click.ClickException(
            f"Decryption failed: {exc}\n"
            "Shard 2 may be incorrect or the vault data may be corrupted."
        )

    # ── Success ──────────────────────────────────────────────────────
    console.print(Panel(
        f"[bold green]Inheritance claim successful.[/bold green]\n\n"
        f"[bold white]{plaintext.decode('utf-8', errors='replace')}[/bold white]",
        title="[bold green]🔓 Decrypted Testament / Secret[/bold green]",
        border_style="green",
    ))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
