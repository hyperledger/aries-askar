import type { Store } from 'aries-askar-shared'

import { setupWallet } from './utils'

describe('Store and Session', () => {
  let store: Store

  beforeEach(async () => {
    store = await setupWallet()
  })

  afterEach(async () => {
    await store.close(true)
  })

  test('Insert', async () => {
    const session = await store.openSession()

    const testEntry = {
      category: 'test category',
      name: 'test name',
      value: 'ja',
      tags: { '~plaintag': 'a', enctag: 'a' },
    }

    await session.insert(testEntry)

    await expect(session.count(testEntry)).resolves.toStrictEqual(1)

    await session.close()
  })

  test('Replace', async () => {
    const session = await store.openSession()
    const testEntry = {
      category: 'test category',
      name: 'test name',
      value: 'foo',
      tags: { '~plaintag': 'a', enctag: 'a' },
    }

    await session.insert(testEntry)

    await expect(session.count(testEntry)).resolves.toStrictEqual(1)

    const updatedEntry = { ...testEntry, value: 'bar', tags: { update: 'baz' } }

    await session.replace(updatedEntry)

    await expect(session.count(updatedEntry)).resolves.toStrictEqual(1)

    await session.close()
  })

  test('Remove', async () => {
    const session = await store.openSession()
    const testEntry = {
      category: 'test category',
      name: 'test name',
      value: 'ja',
      tags: { '~plaintag': 'a', enctag: 'a' },
    }

    await session.insert(testEntry)

    await expect(session.count(testEntry)).resolves.toStrictEqual(1)

    await session.remove(testEntry)

    await expect(session.count(testEntry)).resolves.toStrictEqual(0)

    await session.close()
  })

  test('Remove all', async () => {
    const session = await store.openSession()
    const testEntry = {
      category: 'test category',
      name: 'test name',
      value: 'ja',
      tags: { '~plaintag': 'a', enctag: 'a' },
    }

    const secondEntry = {
      ...testEntry,
      name: 'foo',
    }

    await session.insert(testEntry)
    await session.insert(secondEntry)

    await expect(session.count(testEntry)).resolves.toStrictEqual(2)

    await session.removeAll({ category: testEntry.category })

    await expect(session.count(testEntry)).resolves.toStrictEqual(0)

    await session.close()
  })

  // TODO: why is scan receiving a null ptr?
  test('Scan', async () => {
    const session = await store.openSession()
    const firstEntry = {
      category: 'a',
      name: 'test name o',
      value: 'jaja',
      tags: { '~plaintag': 'b' },
    }

    await session.insert(firstEntry)

    const found = await store.scan(firstEntry).fetchAll()
    expect(found[0]).toMatchObject(firstEntry)

    await session.close()
  })

  test('Basic transaction', async () => {
    const txn = await store.openSession(true)

    const firstEntry = {
      category: 'a',
      name: 'test name o',
      value: 'jaja',
      tags: { '~plaintag': 'b' },
    }

    await txn.insert(firstEntry)

    await expect(txn.count(firstEntry)).resolves.toStrictEqual(1)

    await expect(txn.fetch(firstEntry)).resolves.toMatchObject(firstEntry)

    const found = await txn.fetchAll(firstEntry)

    // TODO: value seems to have double quotes.
    expect(found[0]).toMatchObject({ category: 'a' })

    await txn.close()
  })
})
