//! `wimsey` command-line tool.
//!
//! Phase 4 will grow this into `issue` / `verify` / `inspect` subcommands.
//! For now it only reports its version so the workspace has a runnable binary.

fn main() {
    println!("wimsey {}", env!("CARGO_PKG_VERSION"));
    println!("A vendor-neutral WIMSE reference implementation in Rust.");
    println!("Subcommands land in Phase 4 — see ROADMAP.md.");
}
