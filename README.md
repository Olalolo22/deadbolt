# ⚡ DeadBolt: Autonomous Digital Trust & Succession Protocol

> **The Frankenstein Stitch:** 500-year-old Fiduciary Trust & Estate Succession Law stitched into an autonomous cryptographic heartbeat state machine. Zero lawyers, zero custodians, zero court delays.

Built for **[Kiroween 2026](https://kiroween.devpost.com/)** (*Frankenstein Track*).

---

## 💀 The Problem: The $140B Digital Graveyard
When an individual unexpectedly passes away with self-custodied digital assets (Bitcoin, Solana, private seeds, encrypted credentials):
1. **The Seed Phrase Trap:** Writing seed phrases or private keys into a traditional legal will is financial suicide—wills enter public probate court upon death, exposing keys to clerks, executors, and bad actors.
2. **The Permanent Loss:** If keys are kept strictly in the owner's head or a private vault, the capital is burned forever. Over 20% of all Bitcoin is estimated to be permanently lost this way.

---

## 🔮 The Solution: DeadBolt
DeadBolt is an autonomous, non-custodial digital trust:
- **Client-Side Sharding:** Your secrets (seed phrases, private keys, testament letters) are encrypted client-side via AES-256-GCM and split into a **2-of-3 Shamir threshold**.
- **Heartbeat State Machine:** You configure a check-in cadence (e.g. 30 days). A 1-click magic ping resets your timer.
- **Fail-Safe Grace Period:** If you miss check-ins, the protocol enters a 14-day high-priority alarm grace window.
- **Autonomous Release:** If the grace window elapses with zero response, the protocol confirms the deceased state and publishes the missing shard. Your designated heir combines their dormant token with the published shard to claim their inheritance.

---

## 🧠 Engineered with Kiro (`/.kiro`)

DeadBolt is built natively with Kiro's spec-driven development architecture:

- **`/.kiro/steering/security-invariants.md`**: Strict non-negotiable cryptographic rules that govern all agent code generation (Zero Custody, Mandatory Grace Period, Non-Repudiation).
- **`/.kiro/specs/deadbolt-core/`**:
  - `requirements.md`: Formal user stories, functional requirements, and failure models.
  - `design.md`: State transition table and 2-of-3 Shamir cryptographic architecture.
  - `tasks.md`: Incremental implementation plan executed in Kiro Spec Mode.
- **`/.kiro/hooks/`**: Automated invariant test runners that verify zero early-release vulnerabilities on file save.

---

## 🛠️ Quickstart

Open this repository in **Kiro IDE** or run via **Kiro CLI**:
```bash
# Clone and open in Kiro
cd deadbolt
kiro .
```
Kiro will automatically detect `/.kiro/specs/` and load the spec workflow directly into your editor!

