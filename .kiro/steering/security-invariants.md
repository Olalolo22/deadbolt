# DeadBolt Security Invariants & System Steering Rules

These rules are permanent security invariants for DeadBolt. Any code generated, refactored, or audited by the agent must strictly satisfy these constraints.

---

## 1. Zero Custody Invariant (No Cleartext Secret Retention)
- Neither the server, the database, nor the heartbeat monitor may ever possess the full unencrypted secret (seed phrase, private key, or testament letter) at rest.
- Secrets must be encrypted client-side via AES-256-GCM before storage, or split into threshold secret shards (Shamir's Secret Sharing 2-of-3).
- Master decryption keys can only be reconstructed upon verified state transition to `STATE_DECEASED_RELEASED`.

---

## 2. Heartbeat State Machine Invariants
The heartbeat state machine must follow this strict monotonic sequence:
`ACTIVE` -> `PING_MISSED` -> `GRACE_PERIOD` -> `DECEASED_RELEASED`

1. **No Instant Release:** A single missed heartbeat must NEVER trigger a release.
2. **Mandatory Grace Period:** A minimum grace window (default: 14 days) begins only after `N` consecutive failed pings (default: 3 missed intervals).
3. **Escalation Signals:** During `GRACE_PERIOD`, high-priority alerts must be dispatched across all registered channels (Email, Webhook, Telegram/SMS).
4. **Revocability:** At any moment prior to `DECEASED_RELEASED`, a single authenticated owner signature or magic token immediately resets the state machine back to `ACTIVE` and extends the heartbeat expiration timer.

---

## 3. Cryptographic Invariants
- **Non-Repudiation:** Heartbeat check-in tokens must be signed or hashed with single-use nonces to prevent replay attacks.
- **Heir Verification:** The release of encrypted shards or funds is strictly gated to the pre-registered heir public key or verified claimant token.
- **Fail-Safe Immutability:** Once state transitions to `DECEASED_RELEASED`, the transition is permanent and non-reversible to prevent post-mortem inheritance tampering.

