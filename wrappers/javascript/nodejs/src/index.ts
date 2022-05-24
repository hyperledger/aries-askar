/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import { registerAriesAskar, ariesAskar, LogLevel, Store, StoreKeyMethod } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

registerAriesAskar({ askar: new NodeJSAriesAskar() })
ariesAskar.setCustomLogger({ logLevel: LogLevel.Trace })

const testStore = async () => {
  const testStoreUri = 'sqlite://:memory:'
  const key = Store.generateRawKey(new Uint8Array(32).fill(1))
  const store = await Store.provision({
    recreate: true,
    uri: testStoreUri,
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  })

  const session = await store.openSession()
  await session.insert({ category: 'foo', name: 'bar', valueJson: { fobo: 'barra' } })

  process.exit()
}

try {
  void testStore()
} catch (e) {
  console.error('ERROR: ', e)
}
