/* eslint-disable no-console */

import { ariesAskar, Key, KeyAlgs, LogLevel, registerAriesAskar, Store, StoreKeyMethod } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

registerAriesAskar({ askar: new NodeJSAriesAskar() })

process.env.LOG && ariesAskar.setCustomLogger({ logLevel: LogLevel.Trace })

const testStore = async () => {
  try {
    const testStoreUri = 'sqlite://:memory:'
    const testEntry = {
      category: 'test category',
      name: 'test name',
      value: 'test_value',
      tags: { '~plaintag': 'a', enctag: 'a' },
    }

    const key = Store.generateRawKey(Buffer.from('00000000000000000000000000000My1'))
    const store = await Store.provision({
      recreate: true,
      uri: testStoreUri,
      keyMethod: StoreKeyMethod.Raw,
      passKey: key,
    })

    const session = await store.openSession()
    await session.insert(testEntry)
    console.error(await session.count({ category: testEntry.category, tagFilter: testEntry.tags }))
    const result = await session.fetch({ ...testEntry, forUpdate: false })
    console.log(result)

    await session.close()
    await store.close()

    process.exit()
  } catch (e) {
    console.error('ERROR: ', e)
    process.exit(1)
  }
}

// void testStore()

const testKey = async () => {
  const key = Key.fromSeed({ alg: KeyAlgs.Bls12381G2, seed: new Uint8Array(32).fill(0) })
  console.log(key.publicBytes)
  console.log(key.secretBytes)
  const key1 = Key.fromSeed({ alg: KeyAlgs.Bls12381G1, seed: new Uint8Array(32).fill(0) })
  console.log(key1.publicBytes)
  console.log(key1.secretBytes)
}

void testKey()
