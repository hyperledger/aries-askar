/* eslint-disable no-console */

import { ariesAskar, LogLevel, registerAriesAskar, Store, StoreKeyMethod } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

registerAriesAskar({ askar: new NodeJSAriesAskar() })
ariesAskar.setCustomLogger({ logLevel: LogLevel.Trace })

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
    const result = await session.fetch({ ...testEntry, forUpdate: false })
    console.log(result)

    await session.insert(testEntry)

    // console.error(await session.count({ category: testEntry.category, tagFilter: testEntry.tags }))

    await session.close()
    await store.close()

    process.exit()
  } catch (e) {
    console.error('ERROR: ', e)
    process.exit(1)
  }
}

void testStore()
