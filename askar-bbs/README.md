# askar-bbs

[![Rust Crate](https://img.shields.io/crates/v/askar-bbs.svg)](https://crates.io/crates/askar-bbs)
[![Rust Documentation](https://docs.rs/askar-bbs/badge.svg)](https://docs.rs/askar-bbs)

The `askar-bbs` crate provides support for BBS+ signature generation and verification used by [`aries-askar`](https://github.com/hyperledger/aries-askar).

The implementation will be targeting the 2022 standard which is in progress. Please **DO NOT** use this crate and expect it to be compatible with the released version just yet.

## no-std

This crate supports the optional `alloc` feature, gating types and operations that depend on a global allocator. The `std` feature depends on `alloc`, and adds support for `std::error::Error`.

## Quick Start

### Keypairs

Signing and verification keys are managed as `askar-crypto` BLS keypairs. Keys may be generated randomly or from a seed value, or loaded from an binary encoded key or JWK.

```rust
use askar_crypto::{
    alg::bls::{BlsKeyPair, G2}, repr::KeyGen,
};

let keypair = BlsKeyPair::<G2>::random().unwrap();
```

### Signing

```rust
use askar_bbs::{
    io::FixedLengthBytes, DynGenerators, Message, Signature, SignatureBuilder,
};

let messages = [Message::hash("message 1"), Message::hash("message 2")];
let generators = DynGenerators::new(&keypair, messages.len());
let signature = SignatureBuilder::sign(&generators, &keypair, messages.iter().copied()).unwrap();
let signature_bytes = signature.to_bytes();
```

### Verifying a Signature

```rust
let messages = [Message::hash("message 1"), Message::hash("message 2")];
let generators = DynGenerators::new(&keypair, messages.len());
let signature = Signature::from_bytes(&signature_bytes).unwrap();
signature.verify(&generators, messages.iter().copied()).unwrap();
```

### Generating a Signature Proof of Knowledge

This zero-knowledge proof protocol is used by a prover to perform a selective reveal of the signed messages to a verifier.

```rust
let nonce = Nonce::random(); // provided by the verifier
let messages = [Message::hash("message 1"), Message::hash("message 2")];
let generators = DynGenerators::new(&keypair, messages.len());
let signature = Signature::from_bytes(&signature_bytes).unwrap();
let mut prover = signature.prover(&generators);
prover.push_hidden_message(messages[0]).unwrap();
prover.push_message(messages[1]).unwrap();
let (challenge, proof) = prover.complete(nonce).unwrap();
```

### Verifying a Signature Proof of Knowledge

```rust
let mut verifier = proof.verifier(&generators, challenge).unwrap();
verifier.push_hidden_count(1).unwrap();
verifier.push_revealed(messages[1]).unwrap();
let challenge_v = verifier.complete(nonce).unwrap();
verifier.verify(challenge_v).unwrap();
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/hyperledger/aries-askar/blob/main/LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/hyperledger/aries-askar/blob/main/LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
