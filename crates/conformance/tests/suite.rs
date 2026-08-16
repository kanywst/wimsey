//! Runs the committed conformance vectors as part of `cargo test`.
//!
//! The CLI is what other implementers point at their own vector copies; this
//! test is what stops the workspace from shipping an implementation that no
//! longer satisfies its own published contract.

use std::path::PathBuf;

use wimsey_conformance::run::run_dir;

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

#[test]
fn every_vector_passes() {
    let report = run_dir(&conformance_dir()).expect("the vectors load");

    let failures: Vec<String> = report
        .checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| {
            format!(
                "{} {}: {}",
                check.vector,
                check.name,
                check.detail.as_deref().unwrap_or("no detail")
            )
        })
        .collect();

    assert!(
        failures.is_empty(),
        "failed checks:\n{}",
        failures.join("\n")
    );
    assert!(
        report.passed() > 0,
        "the runner found no checks to run, which means the manifest is empty"
    );
}
