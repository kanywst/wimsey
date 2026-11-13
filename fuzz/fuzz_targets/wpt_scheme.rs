//! The `WPT` authentication scheme parser reads an untrusted `Authorization`
//! field value before anything has been verified.
//!
//! The input is taken as raw bytes so a seed is the field value verbatim.
//! Both entry points are fuzzed: the single field value, and the request-level
//! wrapper over however many fields the request carries, one per line.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wimsey_wpt::scheme::{from_credentials, from_request, to_credentials};

fuzz_target!(|data: &[u8]| {
    let Ok(field) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(proof) = from_credentials(field) {
        // Whatever is accepted must survive a round trip unchanged.
        assert_eq!(from_credentials(&to_credentials(proof)).unwrap(), proof);
    }
    let _ = from_request(field.split('\n'));
});
