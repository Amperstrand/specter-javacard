//! SatoChip smartcard client.
//!
//! Wire contract: `protocol.rs` is GENERATED from
//! `tests/host/spec/satochip-protocol.yaml` (validated against the pinned
//! Toporin SatochipApplet tags by `extract_apduchip_spec.py` — see
//! `extract_apdu_spec.py`). The secure channel and client ops implement
//! the hand-curated semantics recorded there; conformance is proven
//! against the vpcd version farm (`bin/conformance.rs`).

pub mod channel;
pub mod client;
pub mod protocol;

pub use client::{Client, Status};
