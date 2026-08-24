//! A JWK is untrusted input twice over: once inside a WIT's `cnf` claim, and
//! again when an issuer's JWKS is fetched. Decoding one runs coordinate parsing
//! and point validation over attacker-controlled bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wimsey_jose::Jwk;

fuzz_target!(|data: &str| {
    if let Ok(jwk) = serde_json::from_str::<Jwk>(data) {
        if let Ok(key) = jwk.to_verifying_key() {
            // Anything that decoded must re-encode to a JWK that decodes again
            // to the same key, or two implementations could disagree about
            // which key a `cnf` claim names.
            let round_trip = Jwk::from_verifying_key(&key);
            assert_eq!(
                round_trip.to_verifying_key().expect("re-decode"),
                key,
                "a JWK must survive a round trip through its key"
            );
        }
    }
});
