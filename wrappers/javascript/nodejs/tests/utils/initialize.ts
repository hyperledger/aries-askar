import { ariesAskar, LogLevel, registerAriesAskar, Store, StoreKeyMethod } from 'aries-askar-shared'

import { NodeJSAriesAskar } from '../../src'

export const getRawKey = () => Store.generateRawKey(Buffer.from('00000000000000000000000000000My1'))
export const testStoreUri = process.env.URI || 'sqlite://:memory:'

export const setup = () => {
  registerAriesAskar({ askar: new NodeJSAriesAskar() })
  process.env.LOG && ariesAskar.setCustomLogger({ logLevel: LogLevel.Trace })
}

export const setupWallet = async () => {
  const key = getRawKey()

  return await Store.provision({
    recreate: true,
    uri: testStoreUri,
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  })
}
