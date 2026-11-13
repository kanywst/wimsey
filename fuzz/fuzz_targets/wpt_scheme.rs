//! The `WPT` authentication scheme parser reads an untrusted `Authorization`
//! field value before anything has been verified.
//!
//! Both entry points are fuzzed: the single field value, and the request-level
//! wrapper over however many fields the request carries.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wimsey_wpt::scheme::{from_credentials, from_request, to_credentials};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    field: &'a str,
    fields: Vec<&'a str>,
}

fuzz_target!(|input: Input<'_>| {
    if let Ok(proof) = from_credentials(input.field) {
        // Whatever is accepted must survive a round trip unchanged.
        assert_eq!(from_credentials(&to_credentials(proof)).unwrap(), proof);
    }
    let _ = from_request(input.fields.iter().copied());
});
