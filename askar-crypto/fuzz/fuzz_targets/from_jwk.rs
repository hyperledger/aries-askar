#![no_main]
use libfuzzer_sys::fuzz_target;

use askar_crypto::{
    alg::AnyKey,
    jwk::{FromJwk, JwkParts},
};

fuzz_target!(|data: JwkParts<'_>| {
    let _ = Box::<AnyKey>::from_jwk_parts(data);
});
