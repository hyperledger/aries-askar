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
      value: 'ja',
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
    // console.error(await session.count({ category: testEntry.category, tagFilter: testEntry.tags }))
    const result = await session.count(testEntry)
    console.log(result === 1)

    const newEntry = { ...testEntry, value: 'new value', tags: { upd: 'tagval' } }

    await session.replace(newEntry)
    const resultAfterUpdate = await session.count(newEntry)
    console.log(resultAfterUpdate === 1)

    await session.remove(newEntry)
    const resultAfterRemove = await session.count(newEntry)
    console.log(resultAfterRemove === 0)

    await session.close()
    await store.close()

    process.exit()
  } catch (e) {
    console.error('ERROR: ', e)
    process.exit(1)
  }
}

void testStore()

// const testKey = async () => {
//   const key = Key.fromSeed({ alg: KeyAlgs.Bls12381G2, seed: new Uint8Array(32).fill(0) })
//   console.log(key.publicBytes)
//   const key1 = Key.fromSeed({ alg: KeyAlgs.Bls12381G1, seed: new Uint8Array(32).fill(0) })
//   console.log(key1.publicBytes)
//   process.exit()
// }
//
// void testKey()
