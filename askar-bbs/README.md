# askar-bbs

[![Rust Crate](https://img.shields.io/crates/v/askar-bbs.svg)](https://crates.io/crates/askar-bbs)
[![Rust Documentation](https://docs.rs/askar-bbs/badge.svg)](https://docs.rs/askar-bbs)

The `askar-bbs` crate provides support for BBS+ signature generation and verification used by [`aries-askar`](https://github.com/hyperledger/aries-askar).

The implementation will be targeting the 2022 standard which is in progress. Please **DO NOT** use this crate and expect it to be compatible with the released version just yet.

## no-std

This crate supports the optional `alloc` feature, gating types and operations that depend on a global allocator. The `std` feature depends on `alloc`, and adds support for `std::error::Error`.
