import '@hyperledger/aries-askar-nodejs'
import { Store, StoreKeyMethod } from '@hyperledger/aries-askar-shared'

export const getRawKey = () => Store.generateRawKey(Buffer.from('00000000000000000000000000000My1'))
export const testStoreUri = process.env.URI || 'sqlite://:memory:'

export const setupWallet = async () => {
  const key = getRawKey()

  return await Store.provision({
    recreate: true,
    uri: testStoreUri,
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  })
}

export const base64url = (str: string) => Buffer.from(str).toString('base64url')
