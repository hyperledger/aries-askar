import type { Store } from 'aries-askar-shared'

import { Key, KeyAlgs, AriesAskarError } from 'aries-askar-shared'

import { firstEntry, secondEntry, setupWallet } from './utils'

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

    await session.insert(firstEntry)

    await expect(session.count(firstEntry)).resolves.toStrictEqual(1)

    await session.close()
  })

  test('Replace', async () => {
    const session = await store.openSession()

    await session.insert(firstEntry)

    await expect(session.count(firstEntry)).resolves.toStrictEqual(1)

    const updatedEntry = { ...firstEntry, value: 'bar', tags: { update: 'baz' } }

    await session.replace(updatedEntry)

    await expect(session.count(updatedEntry)).resolves.toStrictEqual(1)

    await session.close()
  })

  test('Remove', async () => {
    const session = await store.openSession()

    await session.insert(firstEntry)

    await expect(session.count(firstEntry)).resolves.toStrictEqual(1)

    await session.remove(firstEntry)

    await expect(session.count(firstEntry)).resolves.toStrictEqual(0)

    await session.close()
  })

  test('Remove all', async () => {
    const session = await store.openSession()

    await session.insert(firstEntry)
    await session.insert(secondEntry)

    await expect(session.count(firstEntry)).resolves.toStrictEqual(2)

    await session.removeAll({ category: firstEntry.category })

    await expect(session.count(firstEntry)).resolves.toStrictEqual(0)

    await session.close()
  })

  test('Scan', async () => {
    const session = await store.openSession()

    await session.insert(firstEntry)

    const found = await store.scan(firstEntry).fetchAll()
    expect(found[0]).toMatchObject(firstEntry)

    await session.close()
  })

  test('Transaction basic', async () => {
    const txn = await store.openSession(true)

    await txn.insert(firstEntry)

    await expect(txn.count(firstEntry)).resolves.toStrictEqual(1)

    await expect(txn.fetch(firstEntry)).resolves.toMatchObject(firstEntry)

    const found = await txn.fetchAll(firstEntry)

    expect(found[0]).toMatchObject(firstEntry)

    await txn.commit()

    await txn.close()

    const session = await store.openSession()

    await expect(session.fetch(firstEntry)).resolves.toMatchObject(firstEntry)
  })

  test('Key store', async () => {
    const session = await store.openSession()

    const key = Key.generate(KeyAlgs.Ed25519)

    const keyName = 'testKey'

    await session.insertKey({ key, name: keyName, metadata: 'metadata', tags: { a: 'b' } })

    await expect(session.fetchKey({ name: keyName })).resolves.toMatchObject({
      name: keyName,
      tags: { a: 'b' },
      metadata: 'metadata',
    })

    await session.updateKey({ name: keyName, metadata: 'updated metadata', tags: { a: 'c' } })
    const fetchedKey = await session.fetchKey({ name: keyName })
    expect(fetchedKey).toMatchObject({
      name: keyName,
      tags: { a: 'c' },
      metadata: 'updated metadata',
    })

    expect(key.jwkThumbprint === fetchedKey.key.jwkThumbprint).toBeTruthy()

    const found = await session.fetchAllKeys({
      alg: KeyAlgs.Ed25519,
      thumbprint: key.jwkThumbprint,
      tagFilter: { a: 'c' },
    })

    expect(found[0]).toMatchObject({ name: keyName, metadata: 'updated metadata', tags: { a: 'c' } })

    await session.removeKey({ name: keyName })

    await expect(session.fetchKey({ name: keyName })).rejects.toThrowError(AriesAskarError)

    await session.close()
  })

  test('profile', async () => {
    const session = await store.openSession()
    await session.insert(firstEntry)
    await session.close()

    const profile = await store.createProfile()

    const sessionWithProfile = store.session(profile)
    const newSession = await sessionWithProfile.open()
    //Should not find previously stored record
    await expect(newSession.count(firstEntry)).resolves.toStrictEqual(0)
  })
})
