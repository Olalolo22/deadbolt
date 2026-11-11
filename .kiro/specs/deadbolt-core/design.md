# DeadBolt Core Specification: Architecture & Design

## 1. System Architecture Diagram

```
+-------------------------------------------------------------+
|                      DEADBOLT PROTOCOL                      |
+-------------------------------------------------------------+
|                                                             |
|   +-------------------+              +------------------+   |
|   |   VAULT CREATOR   |              |  HEIR / CLAIMANT |   |
|   |      (Owner)      |              |                  |   |
|   +---------+---------+              +--------+---------+   |
|             | Client-side Encrypt             |             |
|             | 2-of-3 Shamir Split             |             |
|             v                                 v             |
|   +-----------------------------------------------------+   |
|   |                DEADBOLT STATE ENGINE                |   |
|   |                                                     |   |
|   |   State Machine:                                    |   |
|   |   [ACTIVE] -> [PING_MISSED] -> [GRACE] -> [RELEASE] |   |
|   |                                                     |   |
|   |   Components:                                       |   |
|   |   - Heartbeat Monitor (Timer Loop)                  |   |
|   |   - Encrypted Vault Storage (Shards & Payloads)     |   |
|   |   - Notification Dispatcher (Multi-channel Alerts)  |   |
|   |   - Threshold Release Module                        |   |
|   +-----------------------------------------------------+   |
|                                                             |
+-------------------------------------------------------------+
```

## 2. State Machine Transitions

| Current State | Event Trigger | Next State | Actions Executed |
|---|---|---|---|
| `ACTIVE` | Owner Check-in Received | `ACTIVE` | Extend `next_checkin_due = now + interval` |
| `ACTIVE` | `now > next_checkin_due` | `PING_MISSED` | Increment missed ping count, dispatch warning |
| `PING_MISSED` | Owner Check-in Received | `ACTIVE` | Reset missed count to 0, extend due date |
| `PING_MISSED` | `missed_count >= MAX_MISSED` | `GRACE_PERIOD` | Start 14-day countdown, dispatch urgent alarms |
| `GRACE_PERIOD` | Owner Check-in Received | `ACTIVE` | Cancel alarms, reset state to active |
| `GRACE_PERIOD` | `now > grace_period_end` | `DECEASED_RELEASED` | Publish time-locked Shard 1, notify Heir |
| `DECEASED_RELEASED` | Any Action | `DECEASED_RELEASED` | Immutable terminal state |

## 3. Cryptographic Key Sharding (2-of-3 Shamir)
1. **Master Key ($K$):** 256-bit random AES key encrypting the secret payload.
2. **Shamir Split:** $K \rightarrow \{S_1, S_2, S_3\}$ where any 2 shards can reconstruct $K$.
   - $S_1$: Stored encrypted in DeadBolt Vault DB. Unlocked ONLY when state = `DECEASED_RELEASED`.
   - $S_2$: Delivered to Heir upon initial vault creation (as a dormant recovery token).
   - $S_3$: Printed / stored offline as paper cold backup.
3. **Reconstruction:** When the owner passes away, $S_1$ becomes public on the claimant portal. Heir supplies $S_2$, reconstructs $K = \text{combine}(S_1, S_2)$, and decrypts the payload client-side in their browser.
