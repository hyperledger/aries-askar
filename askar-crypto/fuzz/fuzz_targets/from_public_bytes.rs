#![no_main]
use libfuzzer_sys::fuzz_target;

use askar_crypto::alg::{AnyKey, AnyKeyCreate, KeyAlg};

fuzz_target!(|data: (KeyAlg, &[u8])| {
    let _ = Box::<AnyKey>::from_public_bytes(data.0, data.1);
});
