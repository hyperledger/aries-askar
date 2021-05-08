#![no_main]
use libfuzzer_sys::fuzz_target;

use askar_crypto::{alg::AnyKey, jwk::FromJwk};

fuzz_target!(|data: &str| {
    let _ = Box::<AnyKey>::from_jwk(data);
});
