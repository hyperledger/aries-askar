# aries-askar-nodejs

Wrapper for Nodejs around Aries Askar

## Requirements

This has been tested extensively with Nodejs version `16.11.0` and `16.15.0`.
Older and newer versions might also work, but they have not been tested.

## Installation

```sh
yarn add aries-askar-nodejs aries-askar-shared
```

## Setup

In order to work with this module a function from `aries-askar-shared` has to be
called to register the native module (aries-askar-nodejs)

```typescript
import { registerAriesAskar } from 'aries-askar-shared'
import { ariesAskarNodeJS } from 'aries-askar-nodejs'

registerAriesAskar({ askar: ariesAskarNodeJS })
```

After this setup classes can be built that are imported from `aries-askar-shared`
and afterwards be submitted as a ledger request, like so:

```typescript
const pool = new PoolCreate({
  parameters: {
    transactions: <TRANSACTION_OBJECT>
  }
})

const getSchemaRequest = new GetSchemaRequest({
  schemaId: 'J6nTnUo3YLayzc2GUUctb1:2:MyName:1.0',
})

await pool.submitRequest({ requestHandle: getSchemaRequest.handle })
```
