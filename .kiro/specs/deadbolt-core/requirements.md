# DeadBolt Core Specification: Requirements

## 1. Problem Statement
Self-custody crypto assets (Solana, EVM, Bitcoin) and private digital credentials (passwords, encrypted notes) have no legal succession mechanism. If a holder dies unexpectedly without sharing seed phrases, 100% of the funds are permanently burned. Conversely, writing seed phrases into traditional legal wills exposes private keys to public probate court records and untrusted executors.

## 2. Product Objectives
DeadBolt bridges traditional fiduciary trust law with autonomous cryptographic release:
- Enable asset owners to deposit encrypted payloads (private keys, recovery seeds, testament letters).
- Maintain an autonomous heartbeat check-in schedule (e.g. 30 days).
- If check-in fails past a configurable grace period, decrypt and stream the payload directly to designated heirs.
- Guarantee zero custody: the server never sees the cleartext key while the owner is alive.

## 3. Functional Requirements

### FR-1: Vault Initialization & Secret Encryption
- **FR-1.1:** Owner creates a DeadBolt Vault specifying:
  - Check-in interval (e.g. 30 days)
  - Grace period (e.g. 14 days)
  - Designated heir contact/public key
  - Secret payload (seed phrase, private key, or markdown letter)
- **FR-1.2:** Secret payload is encrypted client-side using AES-256-GCM. The decryption key is split into a 2-of-3 Shamir threshold:
  - Shard 1: Held by the DeadBolt Autonomous Heartbeat Node (time-locked).
  - Shard 2: Delivered to the Heir (dormant until Shard 1 is published).
  - Shard 3: Held by an independent Guardian/Cold backup.

### FR-2: Heartbeat Monitoring & Ping Dispatch
- **FR-2.1:** System tracks `last_checkin_timestamp` and `next_checkin_due`.
- **FR-2.2:** 7 days before due date, automated reminder pings are dispatched via email/webhook with a single-click authenticated check-in link.
- **FR-2.3:** Submitting a valid check-in resets the timer and updates status to `ACTIVE`.

### FR-3: Grace Period & Alarm Escalation
- **FR-3.1:** If `next_checkin_due` passes without confirmation, state transitions to `PING_MISSED`.
- **FR-3.2:** If 3 consecutive intervals lapse without response, state transitions to `GRACE_PERIOD`.
- **FR-3.3:** Grace period timer activates (e.g. 14 days). Emergency alarms are broadcast across all fallback channels.

### FR-4: Settlement & Heir Inheritance Release
- **FR-4.1:** If grace period expires with zero owner intervention, state permanently transitions to `DECEASED_RELEASED`.
- **FR-4.2:** Shard 1 is published to the claimant portal.
- **FR-4.3:** Designated heir combines Shard 1 + Shard 2 client-side, decrypts the master payload, and claims the assets.
