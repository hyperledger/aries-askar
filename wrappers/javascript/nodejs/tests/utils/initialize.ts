import { ariesAskar, LogLevel, registerAriesAskar, Store, StoreKeyMethod } from 'aries-askar-shared'

import { NodeJSAriesAskar } from '../../src'

export const setupWallet = async () => {
  registerAriesAskar({ askar: new NodeJSAriesAskar() })
  process.env.LOG && ariesAskar.setCustomLogger({ logLevel: LogLevel.Trace })
  const testStoreUri = 'sqlite://:memory:'

  const key = Store.generateRawKey(Buffer.from('00000000000000000000000000000My1'))

  return await Store.provision({
    recreate: true,
    uri: testStoreUri,
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  })
}
