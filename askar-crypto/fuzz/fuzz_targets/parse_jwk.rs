#![no_main]
use libfuzzer_sys::fuzz_target;

use askar_crypto::{alg::AnyKey, jwk::JwkParts};

fuzz_target!(|data: &str| {
    let _ = JwkParts::from_str(data);
});
