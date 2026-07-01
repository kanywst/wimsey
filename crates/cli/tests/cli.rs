//! End-to-end tests that drive the built `wimsey` binary through the full
//! issue -> prove -> verify flow with fixed seeds and an injected clock, so the
//! run is deterministic.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ISSUER_SEED: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const POP_SEED: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
const AUD: &str = "https://workload.example.com/path";

fn wimsey(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wimsey"))
        .args(args)
        .output()
        .expect("run wimsey")
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn generate_key(seed: &str, path: &Path) {
    let output = wimsey(&[
        "key",
        "generate",
        "--seed",
        seed,
        "--out",
        path.to_str().unwrap(),
    ]);
    assert!(output.status.success());
}

#[test]
fn full_issue_prove_verify_flow() {
    let issuer = dir().join("issuer.jwk");
    let pop = dir().join("pop.jwk");
    generate_key(ISSUER_SEED, &issuer);
    generate_key(POP_SEED, &pop);

    // Issue a WIT.
    let wit = stdout(&wimsey(&[
        "wit",
        "issue",
        "--issuer-key",
        issuer.to_str().unwrap(),
        "--cnf-key",
        pop.to_str().unwrap(),
        "--sub",
        "spiffe://example.org/api",
        "--iss",
        "https://issuer.example",
        "--kid",
        "issuer-key-1",
        "--jti",
        "a1b2c3",
        "--now",
        "1700000000",
        "--ttl",
        "3600",
    ]));
    let wit = wit.trim();
    assert_eq!(wit.split('.').count(), 3);

    // Verify the WIT.
    let verified = stdout(&wimsey(&[
        "wit",
        "verify",
        "--issuer-jwk",
        issuer.to_str().unwrap(),
        "--token",
        wit,
        "--expected-iss",
        "https://issuer.example",
        "--now",
        "1700000100",
    ]));
    assert!(verified.contains("spiffe://example.org/api"));
    assert!(verified.contains("issuer-key-1"));

    // Create a WPT bound to the WIT.
    let wpt = stdout(&wimsey(&[
        "wpt",
        "new",
        "--pop-key",
        pop.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        AUD,
        "--jti",
        "0123456789abcdef",
        "--now",
        "1700000000",
        "--ttl",
        "300",
    ]));
    let wpt = wpt.trim();

    // Verify the WPT: this also verifies the bound WIT with the issuer key.
    let verified = stdout(&wimsey(&[
        "wpt",
        "verify",
        "--issuer-jwk",
        issuer.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        AUD,
        "--proof",
        wpt,
        "--now",
        "1700000100",
    ]));
    assert!(verified.contains(AUD));
    assert!(verified.contains("spiffe://example.org/api"));
}

#[test]
fn wit_verify_rejects_the_wrong_issuer_key() {
    let issuer = dir().join("issuer2.jwk");
    let pop = dir().join("pop2.jwk");
    let other = dir().join("other2.jwk");
    generate_key(ISSUER_SEED, &issuer);
    generate_key(POP_SEED, &pop);
    generate_key("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", &other);

    let wit = stdout(&wimsey(&[
        "wit",
        "issue",
        "--issuer-key",
        issuer.to_str().unwrap(),
        "--cnf-key",
        pop.to_str().unwrap(),
        "--sub",
        "spiffe://example.org/api",
        "--iss",
        "https://issuer.example",
        "--now",
        "1700000000",
    ]));

    // Verifying against a different issuer key must fail.
    let output = wimsey(&[
        "wit",
        "verify",
        "--issuer-jwk",
        other.to_str().unwrap(),
        "--token",
        wit.trim(),
        "--now",
        "1700000100",
    ]);
    assert!(!output.status.success());
}

#[test]
fn wpt_verify_rejects_the_wrong_audience() {
    let issuer = dir().join("issuer3.jwk");
    let pop = dir().join("pop3.jwk");
    generate_key(ISSUER_SEED, &issuer);
    generate_key(POP_SEED, &pop);

    let wit = stdout(&wimsey(&[
        "wit",
        "issue",
        "--issuer-key",
        issuer.to_str().unwrap(),
        "--cnf-key",
        pop.to_str().unwrap(),
        "--sub",
        "spiffe://example.org/api",
        "--iss",
        "https://issuer.example",
        "--now",
        "1700000000",
    ]));
    let wit = wit.trim();

    let wpt = stdout(&wimsey(&[
        "wpt",
        "new",
        "--pop-key",
        pop.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        AUD,
        "--now",
        "1700000000",
    ]));

    let output = wimsey(&[
        "wpt",
        "verify",
        "--issuer-jwk",
        issuer.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        "https://evil.example/path",
        "--proof",
        wpt.trim(),
        "--now",
        "1700000100",
    ]);
    assert!(!output.status.success());
}

#[test]
fn wpt_verify_rejects_a_wit_from_the_wrong_issuer() {
    let issuer = dir().join("issuer4.jwk");
    let pop = dir().join("pop4.jwk");
    let other = dir().join("other4.jwk");
    generate_key(ISSUER_SEED, &issuer);
    generate_key(POP_SEED, &pop);
    generate_key("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", &other);

    let wit = stdout(&wimsey(&[
        "wit",
        "issue",
        "--issuer-key",
        issuer.to_str().unwrap(),
        "--cnf-key",
        pop.to_str().unwrap(),
        "--sub",
        "spiffe://example.org/api",
        "--iss",
        "https://issuer.example",
        "--now",
        "1700000000",
    ]));
    let wit = wit.trim();

    let wpt = stdout(&wimsey(&[
        "wpt",
        "new",
        "--pop-key",
        pop.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        AUD,
        "--now",
        "1700000000",
    ]));

    // The proof is valid, but the WIT does not verify under the wrong issuer
    // key, so the whole verification must fail closed.
    let output = wimsey(&[
        "wpt",
        "verify",
        "--issuer-jwk",
        other.to_str().unwrap(),
        "--wit",
        wit,
        "--aud",
        AUD,
        "--proof",
        wpt.trim(),
        "--now",
        "1700000100",
    ]);
    assert!(!output.status.success());
}
