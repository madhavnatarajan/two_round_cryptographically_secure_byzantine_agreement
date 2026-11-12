# Project Notes

## What this project is

An interactive demo of a 2-round Byzantine Agreement protocol, plus a test harness for verifying it.
The protocol is based on the paper "Cryptographically Secure Domain Extension for Byzantine Agreement
with Improved Round Complexity" (ACM PODC 2026).

---

## Workspace Structure

```
projects/
├── harness/              ← shared protocol logic + test infrastructure
│   └── src/
│       ├── adversary.rs  ← Behavior, Node, P2PMessage
│       ├── protocol.rs   ← Simulation, round logic (RS + Merkle)
│       ├── network.rs    ← (planned) message delay · drop · reorder
│       ├── grader.rs     ← (planned) agreement · validity · termination
│       └── trace.rs      ← (planned) event log, seeded replay
├── protocols/
│   └── ba2r/             ← the 2-round BA as a consumer of harness
│       └── src/main.rs   ← Axum HTTP server only, imports from harness
└── index.html            ← browser UI / run dashboard
```

---

## What each file does

### `harness/src/adversary.rs`
Defines node types and fault behaviors:
- `Behavior` — Honest, Mute, Liar (Equivocator planned)
- `Node` — holds id, input, behavior
- `P2PMessage` — the shard + Merkle proof a node sends to others
- `Node::execute_round_1` — RS encodes input, builds Merkle tree, sends shards (liars corrupt theirs)

### `harness/src/protocol.rs`
Pure protocol logic, no HTTP, no server:
- `Simulation::run_round_1` — each node broadcasts its Merkle root to the BB oracle (whiteboard)
- `Simulation::identify_core` — finds the set of n-t nodes that agree on the same root
- `Simulation::run_round_2` — non-CORE nodes collect shards from CORE, verify via Merkle proofs,
  reconstruct via RS decoding. Outputs ⊥ if no CORE formed.

### `harness/src/network.rs` (planned)
Simulates the network between nodes — message delays, drops, reordering.
Lets you test the protocol under bad network conditions, not just bad nodes.

### `harness/src/grader.rs` (planned)
After a run, checks the three formal BA properties:
- **Agreement** — did all honest nodes output the same value?
- **Validity** — is the output a value that some honest node actually input?
- **Termination** — did every honest node eventually output something?

### `harness/src/trace.rs` (planned)
Records every event in a run with a seed so you can replay it deterministically.
Critical for debugging AI-generated failing test cases.

### `protocols/ba2r/src/main.rs`
Thin Axum HTTP server — just routes and handlers. All logic imported from `harness`.
Endpoints: `/start`, `/round1`, `/round2`, `/status`

---

## What "harness" means here

A test harness is infrastructure that sits *around* the thing being tested.
It is not the protocol — it is the scaffolding that lets you run the protocol
under controlled, repeatable conditions and check whether it behaved correctly.

The planned AI test generation loop:
```
AI generates scenario (n, t, fault config, network conditions)
    → adversary.rs models the faults
    → network.rs models the delivery
    → protocol runs
    → grader.rs checks agreement · validity · termination
    → trace.rs logs it for replay if it fails
    → result fed back to AI to explore more of the fault space
```

---

## Key engineering decisions

### Why `Arc<Mutex<AppState>>`?
- `Arc` — shared ownership of state across async handlers (atomic reference counting)
- `Mutex` — only one handler can write at a time, prevents data races
- Rust enforces this at compile time — impossible to share mutable state without it

### Why split `/start`, `/round1`, `/round2`?
The protocol is a state machine. Splitting into steps lets the UI show intermediate
state (whiteboard, CORE set) before Round 2 runs. Each endpoint guards against
being called out of order.

### Why Reed-Solomon with `t+1` data shards?
With `t` faulty nodes, you are guaranteed at least `t+1` honest responses.
Setting data shards = `t+1` means those honest responses are always sufficient
to reconstruct — the threshold is not arbitrary, it encodes the fault tolerance bound.

### Why Merkle proofs instead of hashing the full message?
A node receiving one shard can verify it belongs to the committed root in O(log n)
space, without seeing all other shards. The proof is just the sibling hashes up
the tree — `log₂(n)` hashes total.

### Why a Cargo workspace?
`harness` is a library crate shared across protocol consumers (`ba2r`, `mpc_sum` later).
A workspace lets both crates share a single `Cargo.lock` and build cache while
keeping their concerns cleanly separated.

---

## Running

```bash
cargo run -p ba2r
```

Then open `index.html` in your browser.
