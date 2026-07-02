# Round-Optimal Domain Extension for Cryptographically Secure Byzantine Agreement Demo

An interactive demo of the cryptographically secure domain extension protocol for Byzantine Agreement, implemented in Rust with a browser-based UI.

## How it works

The protocol runs in 2 rounds across `n` nodes, tolerating up to `t` faulty nodes (requires `n > 2t`):

- **Round 1:** Each honest node Reed-Solomon encodes its input, builds a Merkle tree over the shards, and broadcasts its Merkle root to a BB oracle (whiteboard). The system identifies a `CORE` set of `n-t` nodes that agree on the same root.
- **Round 2:** Non-CORE nodes collect shards from CORE members, verify each shard against the agreed Merkle root, and reconstruct the original message from any `t+1` valid components. Corrupted data from liars is detected and rejected via Merkle proof verification.

Node behaviors can be set to **Honest**, **Mute** (silent), or **Liar** (sends corrupted shards).

## Running

Requires [Rust](https://rustup.rs/).

```bash
cargo run
```

Then open `index.html` directly in your browser. The UI connects to the server at `http://127.0.0.1:3000`.

## Stack

- **Backend:** Rust, [Axum](https://github.com/tokio-rs/axum), Reed-Solomon (`reed-solomon-erasure`), Merkle trees (`rs_merkle`)
- **Frontend:** Single-file HTML with React (CDN) and Tailwind CSS (CDN)

## Paper

This demo is based on the research paper **"Cryptographically Secure Domain Extension for Byzantine Agreement with Improved Round Complexity"**, to be published at [ACM PODC 2026](https://www.podc.org/).

> 📄 [Read the full paper](https://dl.acm.org/doi/10.1145/3796701.3815921)

If you find this work useful, consider citing it!