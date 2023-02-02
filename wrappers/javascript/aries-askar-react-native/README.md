# Aries Askar React Native

Wrapper for React Native around Aries Askar

## Requirements

This module uses the new React Native Turbo Modules. These are faster than the
previous Native Modules, and can be completely synchronous. A React Native
version of `>= 0.66.0` is required for this package to work.

## Installation

```sh
yarn add @hyperledger/aries-askar-react-native
```

## Setup

You can import all types and classes from the `@hyperledger/aries-askar-react-native` library:

```typescript
import { Key, KeyAlgs } from '@hyperledger/aries-askar-react-native'

const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'))
const key = Key.fromSeed({ algorithm: KeyAlgs.Bls12381G1, seed })
```

> **Note**: If you want to use this library in a cross-platform environment you need to import methods from the `@hyperledger/aries-askar-shared` package instead. This is a platform independent package that allows to register the native bindings. The `@hyperledger/aries-askar-react-native` package uses this package under the hood. See the [Aries Askar Shared README](https://github.com/hyperledger/aries-askar/tree/main/wrappers/javascript/aries-askar-shared/README.md) for documentation on how to use this package.
