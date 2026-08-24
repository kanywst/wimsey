//! Workload identifier parsing must reject anything malformed without panicking.
//!
//! The parser slices `uri` by byte offsets it computed itself — the scheme
//! prefix length plus the trust domain length — so a mistake there is an
//! out-of-bounds or a char-boundary panic on attacker-controlled input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wimsey_identifier::WorkloadIdentifier;

fuzz_target!(|data: &str| {
    if let Ok(id) = WorkloadIdentifier::parse(data) {
        // Every accessor slices the stored string; exercise all of them.
        let scheme = id.scheme();
        let trust_domain = id.trust_domain();
        let path = id.path();
        let origin = id.origin();

        assert_eq!(id.as_str(), data, "parsing must not rewrite the input");
        assert!(
            id.as_str().starts_with(origin),
            "the origin must be a prefix of the identifier"
        );
        assert_eq!(
            origin.len() + path.len(),
            id.as_str().len(),
            "origin and path must partition the identifier"
        );
        assert!(!trust_domain.is_empty(), "an accepted trust domain is non-empty");
        assert!(origin.starts_with(scheme.as_str()));

        // Re-parsing what we accepted must land in the same place, which is the
        // property whole-URI comparison depends on.
        let again = WorkloadIdentifier::parse(id.as_str()).expect("re-parse an accepted identifier");
        assert_eq!(again, id);
    }
});
