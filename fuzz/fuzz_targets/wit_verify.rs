//! WIT verification runs over an untrusted compact JWS: three base64url parts,
//! a JSON header and a JSON claim set, all attacker-controlled.
//!
//! The key and clock are fixed so the fuzzer spends its budget on the parser
//! rather than on guessing signatures. Nothing should ever verify; what is
//! being tested is that every rejection is a returned error.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wimsey_wit::{verify, SigningKey, Validation};

fuzz_target!(|data: &str| {
    let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
    let _ = verify(data, &key, &Validation::at(1_700_000_000));
    let _ = verify(
        data,
        &key,
        &Validation::at(1_700_000_000)
            .with_leeway(60)
            .expect_issuer("https://issuer.example"),
    );
});
