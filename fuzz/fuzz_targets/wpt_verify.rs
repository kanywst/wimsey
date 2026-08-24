//! WPT verification parses an untrusted compact JWS and then recomputes the
//! `wth` binding over a caller-supplied WIT.
//!
//! Both halves are fuzzed: the proof itself, and the WIT string it is bound to.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wimsey_wpt::{verify, SigningKey, Validation};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    proof: &'a str,
    wit: &'a str,
    audience: &'a str,
    access_token: Option<&'a str>,
}

fuzz_target!(|input: Input<'_>| {
    let mut validation = Validation::new(1_700_000_000, input.audience, input.wit);
    validation.access_token = input.access_token;
    for key in [
        SigningKey::from_ed25519_seed(&[9u8; 32]),
        SigningKey::from_p256_scalar(&[9u8; 32]).expect("a fixed valid scalar"),
    ] {
        let _ = verify(input.proof, &key.verifying_key(), &validation);
    }
});
