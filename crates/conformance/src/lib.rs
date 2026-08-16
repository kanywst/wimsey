//! Generator and runner for the WIMSE cross-implementation conformance vectors.
//!
//! The vectors under `conformance/` are a contract: any WIMSE implementation
//! should be able to read them, reproduce the recorded bytes from the recorded
//! inputs, accept the positive cases, and **reject every negative case with the
//! recorded reason**. This crate owns both halves of that contract — the
//! generator that writes the files and the runner that checks them — so the
//! format has exactly one definition and cannot drift between the two.
//!
//! ```text
//! wimsey-conformance generate --out conformance   # write the vectors
//! wimsey-conformance run --dir conformance        # check them
//! ```
//!
//! The format itself is documented for other implementers in
//! `conformance/README.md`.

pub mod generate;
pub mod run;
pub mod vectors;
