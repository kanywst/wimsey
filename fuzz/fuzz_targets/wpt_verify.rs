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
    let key = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let mut validation = Validation::new(1_700_000_000, input.audience, input.wit);
    validation.access_token = input.access_token;
    let _ = verify(input.proof, &key, &validation);
});
