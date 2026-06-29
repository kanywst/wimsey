//! `wimsey-wpt` — WIMSE Workload Proof Token (WPT).
//!
//! Target spec: `draft-ietf-wimse-wpt-01`. A signed JWT carrying `aud`, `exp`,
//! `jti` and `wth` (a hash of the bound WIT), media type
//! `application/wimse-proof+jwt`. DPoP-inspired proof of possession.
//!
//! Phase 2 — implementation pending. See `ROADMAP.md`.
