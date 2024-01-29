# Aries Askar NodeJS

Wrapper for Nodejs around Aries Askar

## Requirements

This library requires (and has been tested extensively with) Node.js version `18.x`. Newer versions might also work, but they have not been tested.

## Installation

```sh
yarn add @hyperledger/aries-askar-nodejs
```

## Setup

You can import all types and classes from the `@hyperledger/aries-askar-nodejs` library:

```typescript
import { Key, KeyAlgs } from '@hyperledger/aries-askar-nodejs'

const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'))
const key = Key.fromSeed({ algorithm: KeyAlgs.Bls12381G1, seed })
```

> **Note**: If you want to use this library in a cross-platform environment you need to import methods from the `@hyperledger/aries-askar-shared` package instead. This is a platform independent package that allows to register the native bindings. The `@hyperledger/aries-askar-nodejs` package uses this package under the hood. See the [Aries Askar Shared README](https://github.com/hyperledger/aries-askar/tree/main/wrappers/javascript/aries-askar-shared/README.md) for documentation on how to use this package.

## Version Compatibility

The JavaScript wrapper is versioned independently from the native bindings. The following table shows the compatibility between the different versions:

| Aries Askar | JavaScript Wrapper |
| ----------- | ------------------ |
| v0.2.9      | v0.1.0, v0.1.1     |
| v0.3.1      | v0.2.0             |
