//! WIC handling parses DER X.509 from the wire, then reads a URI SAN out of it
//! and hands the result to the identifier parser.
//!
//! Both entry points are fuzzed. `verify` additionally walks a second untrusted
//! certificate as the trust anchor, which is how a peer-supplied chain would
//! reach the code in a caller that does not pin its CA.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wimsey_mtls::{verify, workload_identifier};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    certificate: &'a [u8],
    ca: &'a [u8],
    now: u64,
}

fuzz_target!(|input: Input<'_>| {
    let _ = workload_identifier(input.certificate);
    let _ = verify(input.certificate, input.ca, input.now);
});
