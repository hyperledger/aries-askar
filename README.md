# aries-askar

[![Unit Tests](https://github.com/hyperledger/aries-askar/workflows/Aries-Askar/badge.svg)](https://github.com/hyperledger/aries-askar/actions)
[![Rust Crate](https://img.shields.io/crates/v/aries-askar.svg)](https://crates.io/crates/aries-askar)
[![Rust Documentation](https://docs.rs/aries-askar/badge.svg)](https://docs.rs/aries-askar)
[![Python Package](https://img.shields.io/pypi/v/aries_askar)](https://pypi.org/project/aries-askar/)

Aries Askar is a secure (encrypted at rest) storage and a key management service
suitable for use with [Hyperledger Aries] agents and possibly other digital
trust agents. Askar is a replacement implementation (with lessons learned!) of the
[indy-wallet] part of the [Hyperledger Indy SDK]. Askar has been demonstrated to
be more performant and stable than the Indy SDK when under comparable load.

Askar has a pluggable storage interface that currently supports in-memory (for
testing only), [SQLite] and [PostgreSQL] databases. For details about the
storage scheme used in Askar, please this [storage] overview in the `docs`
folder.

Askar is implemented in Rust and this repository contains Askar wrappers for
Askar JavaScript and Python, reflecting the key Aries frameworks that embed
Askar, [Aries Framework JavaScript] and [Aries Cloud Agent Python]. Other
wrappers are welcome, although there is some debate as to whether the wrappers
should be within this repository or in their own repository.

The name Askar (from the Arabic askar, meaning “guard” or “soldier”) is used
because of the "guard" reference, and because it is an alternate name for the
star [Hamal in the constellation of Aries], the 50th brightest star in our sky.

[Hyperledger Aries]: https://www.hyperledger.org/projects/aries
[indy-wallet]: https://github.com/hyperledger/indy-sdk/tree/main/libindy/indy-wallet
[Hyperledger Indy SDK]: https://github.com/hyperledger/indy-sdk
[SQLite]: https://www.sqlite.org/index.html
[PostgreSQL]: https://www.postgresql.org/
[storage]: /docs/storage.md
[Aries Framework JavaScript]: https://github.com/hyperledger/aries-framework-javascript
[Aries Cloud Agent Python]: https://github.com/hyperledger/aries-cloudagent-python
[Hamal in the constellation of Aries]: https://www.star-facts.com/hamal/

## Askar Concepts Borrowed from the indy-wallet Implementation

As noted above, Askar is a re-implementation (with lessons learned!) of the
[indy-wallet] part of the [Hyperledger Indy SDK]. As such, a number of the
concept documents written about [indy-wallet] apply similarly to Askar. These
are linked here:

* [Encryption and storage passphrases](https://github.com/hyperledger/indy-sdk/blob/main/docs/concepts/default-wallet.md)
* [Object Storage](https://github.com/hyperledger/indy-sdk/blob/main/docs/design/003-wallet-storage/README.md)
* [Storage Import/Export](https://github.com/hyperledger/indy-sdk/blob/main/docs/design/009-wallet-export-import/README.md)

> **To Do**: These documents should be copied to this repository and updated
> specifically for the Askar implementation.

## Migrating to Aries Askar

If you have an implementation of Aries that is currently based on the [Hyperledger Indy SDK], there are migration tools
built into Askar. The use of these tools is demonstrated in the [Aries Cloud Agent Python] migration tool that can be
found in the [aries-acapy-tools] repository.

[aries-acapy-tools]: https://github.com/hyperledger/aries-acapy-tools

## Credit

The initial implementation of `aries-askar` was developed by the Digital Trust
team within the Province of British Columbia, and inspired by the wallet design
within [Hyperledger Indy SDK]. To learn
more about BC's Digital Trust Team, and what's happening with decentralized identity in British
Columbia, please go to [Digital Trust website](https://digital.gov.bc.ca/digital-trust/).

## Contributing

Pull requests are welcome! Please read our [contributions guide](https://github.com/hyperledger/aries-askar/blob/main/CONTRIBUTING.md) and submit your PRs. We enforce [developer certificate of origin](https://developercertificate.org/) (DCO) commit signing. See guidance [here](https://github.com/apps/dco).

We also welcome issues submitted about problems you encounter in using `aries-askar`.

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](https://github.com/hyperledger/aries-askar/blob/main/LICENSE-APACHE)
  or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license
  ([LICENSE-MIT](https://github.com/hyperledger/aries-askar/blob/main/LICENSE-MIT)
  or [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))

at your option.
