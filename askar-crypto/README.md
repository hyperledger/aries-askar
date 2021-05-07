# askar-crypto

[![Rust Crate](https://img.shields.io/crates/v/askar-crypto.svg)](https://crates.io/crates/askar-crypto)
[![Rust Documentation](https://docs.rs/askar-crypto/badge.svg)](https://docs.rs/askar-crypto)

The `askar-crypto` crate provides the basic key representations and cryptographic operations used by [`aries-askar`](https://github.com/hyperledger/aries-askar).

## Supported Key Types

| Key Type             | Feature   | Operations                                                                                                                     | Notes                           |
| -------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------- |
| AES-GCM              | `aes`     | AEAD encryption<br>JWK export                                                                                                  | A128GCM and A256GCM             |
| AES-CBC-HMAC-SHA2    | `aes`     | AEAD encryption<br>JWK export                                                                                                  | A128CBC-HS256 and A256CBC-HS512 |
| (X)ChaCha20-Poly1305 | `chacha`  | AEAD encryption<br>JWK export                                                                                                  | aka C20P, XC20P                 |
| BLS12-381            | `bls`     | [`bls-signature`](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04)-compatible key generation<br>JWK import/export | G1, G2, and G1G2 key types      |
| Ed25519              | `ed25519` | EdDSA signatures<br>JWK import/export                                                                                          |                                 |
| X25519               | `ed25519` | DH key exchange<br>JWK import/export                                                                                           |                                 |
| K-256                | `k256`    | ECDSA signatures<br>DH key exchange<br>JWK import/export                                                                       | aka secp256k1                   |
| P-256                | `p256`    | ECDSA signatures<br>DH key exchange<br>JWK import/export                                                                       | aka nist256p1, secp256r1        |

## 'Any' Key support

The `any_key` feature (which depends on `alloc`) provides a generic interface for creating and working with any supported key type.

## JOSE Authenticated Encryption

This crate provides implementations of the [ECDH-ES](https://tools.ietf.org/html/rfc7518#section-4.6) and [ECDH-1PU (draft 4)](https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04) key agreement operations, for use in deriving the CEK or key wrapping key when producing or consuming JWE envelopes using these protection algorithms.

## no-std

This crate supports the optional `alloc` feature, gating types and operations that depend on a global allocator. The `std` feature depends on `alloc`, and adds support for `std::error::Error`.
