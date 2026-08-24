//! The RFC 9421 structured-field parser is the most exposed surface in the
//! workspace: `Signature-Input` and `Signature` arrive from the network, and
//! the parser is quote-aware, hand-written, and must reconstruct the signature
//! base byte-for-byte from what it read.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wimsey_httpsig::{verify, Component, HttpRequest, SigningKey, VerifyConfig};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    signature_input: &'a str,
    signature: &'a str,
    header_name: &'a str,
    header_value: &'a str,
    wimse_profile: bool,
}

fuzz_target!(|input: Input<'_>| {
    let key = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
    let request = HttpRequest {
        method: "POST".to_owned(),
        authority: "service.example".to_owned(),
        path: "/transfer".to_owned(),
        query: None,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            (input.header_name.to_owned(), input.header_value.to_owned()),
        ],
    };
    let config = VerifyConfig {
        now: Some(1_700_000_000),
        required_components: vec![Component::Method, Component::RequestTarget],
        wimse_profile: input.wimse_profile,
        ..VerifyConfig::default()
    };
    let _ = verify(
        &request,
        input.signature_input,
        input.signature,
        &key,
        &config,
    );
});
