# DeadBolt Core Specification: Implementation Tasks

This task list is consumed by Kiro's Spec-driven development engine.

---

- [x] **Task 1: Core Cryptographic Sharding Engine**
  - Implement AES-256-GCM symmetric encryption/decryption utilities.
  - Implement 2-of-3 Shamir's Secret Sharing (SSS) key splitter and reconstructor.
  - Write unit tests verifying: $K = \text{combine}(S_1, S_2) = \text{combine}(S_1, S_3) = \text{combine}(S_2, S_3)$.
  - Verify that a single shard reveals zero information about $K$.

- [x] **Task 2: Heartbeat State Machine Engine**
  - Implement the `HeartbeatVault` data model with timestamps, intervals, and state enums.
  - Implement state transition methods: `record_checkin()`, `tick()`, `trigger_grace()`, `finalize_release()`.
  - Enforce monotonic state rules and immutability once `DECEASED_RELEASED`.

- [x] **Task 3: Invariant Fuzzing & Property Tests**
  - Write property-based tests verifying the **Zero Early Release** invariant: no combination of ticks or missed pings prior to `grace_period_end` can expose Shard 1.
  - Verify that an owner check-in during `GRACE_PERIOD` immediately reverts state to `ACTIVE`.

- [x] **Task 4: CLI & Interactive Demonstration Surface**
  - Build a high-impact terminal CLI / simulation script:
    - `deadbolt init`: Creates a new vault, encrypts payload, and outputs Shard 2 to heir.
    - `deadbolt checkin`: Authenticated owner check-in simulating health status.
    - `deadbolt fast-forward --days 45`: Fast-forwards simulation clock to demonstrate missed pings and grace period.
    - `deadbolt claim`: Heir submits Shard 2 and receives decrypted testament/funds.

- [x] **Task 5: Kiro Agent Hooks & CI Integration**
  - Configure `.kiro/hooks/` to run cryptographic property tests whenever state transition code is edited.

