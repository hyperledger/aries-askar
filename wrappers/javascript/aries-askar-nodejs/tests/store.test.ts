import { Store, StoreKeyMethod, Key, KeyAlgs, AriesAskarError, KdfMethod } from '@hyperledger/aries-askar-shared'
import { promises } from 'fs'

import { firstEntry, getRawKey, secondEntry, setupWallet, testStoreUri } from './utils'

describe('Store and Session', () => {
  let store: Store

  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  beforeEach(async () => {
    store = await setupWallet()
  })

  afterEach(async () => {
    await store.close(true)
  })

  test('argon2i mod', async () => {
    const argon2iModStore = await Store.provision({
      recreate: true,
      passKey: 'abc',
      uri: testStoreUri,
      keyMethod: new StoreKeyMethod(KdfMethod.Argon2IMod),
    })

    const session = await argon2iModStore.openSession()
    await expect(session.fetch({ name: 'unknownKey', category: 'unknownCategory' })).resolves.toBeNull()

    await argon2iModStore.close()
  })

  test('argon2i int', async () => {
    const argon2iIntStore = await Store.provision({
      recreate: true,
      passKey: 'abc',
      uri: testStoreUri,
      keyMethod: new StoreKeyMethod(KdfMethod.Argon2IInt),
    })

    const session = await argon2iIntStore.openSession()
    await expect(session.fetch({ name: 'unknownKey', category: 'unknownCategory' })).resolves.toBeNull()

    await argon2iIntStore.close()
  })

  test('Rekey', async () => {
    const initialKey = Store.generateRawKey()

    // Make sure db directory exists
    const storagePath = './tmp'
    try {
      await promises.access(storagePath)
    } catch {
      await promises.mkdir(storagePath)
    }

    let newStore = await Store.provision({
      recreate: true,
      profile: 'rekey',
      uri: `sqlite://${storagePath}/rekey.db`,
      keyMethod: new StoreKeyMethod(KdfMethod.Raw),
      passKey: initialKey,
    })

    const newKey = Store.generateRawKey()
    await newStore.rekey({ keyMethod: new StoreKeyMethod(KdfMethod.Raw), passKey: newKey })

    await newStore.close()

    await expect(
      Store.open({
        profile: 'rekey',
        uri: `sqlite://${storagePath}/rekey.db`,
        keyMethod: new StoreKeyMethod(KdfMethod.Raw),
        passKey: initialKey,
      })
    ).rejects.toThrowError(AriesAskarError)

    newStore = await Store.open({
      profile: 'rekey',
      uri: `sqlite://${storagePath}/rekey.db`,
      keyMethod: new StoreKeyMethod(KdfMethod.Raw),
      passKey: newKey,
    })

    await newStore.close(true)
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
    await session.insert(secondEntry)
    const found = await store.scan({ category: firstEntry.category }).fetchAll()
    expect(found.length).toBe(2)
    // value is converted to string, so we expect it as string at this level
    expect(found).toEqual(
      expect.arrayContaining([firstEntry, { ...secondEntry, value: JSON.stringify(secondEntry.value) }])
    )

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

    const session = await store.openSession()

    await expect(session.fetch(firstEntry)).resolves.toMatchObject(firstEntry)
  })

  test('Key store', async () => {
    const session = await store.openSession()

    const key = Key.generate(KeyAlgs.Ed25519)

    const keyName = 'testKey'

    await session.insertKey({ key, name: keyName, metadata: 'metadata', tags: { a: 'b' } })

    const fetchedKey1 = await session.fetchKey({ name: keyName })
    expect(fetchedKey1).toMatchObject({
      name: keyName,
      tags: { a: 'b' },
      metadata: 'metadata',
    })

    await session.updateKey({ name: keyName, metadata: 'updated metadata', tags: { a: 'c' } })
    const fetchedKey2 = await session.fetchKey({ name: keyName })
    expect(fetchedKey2).toMatchObject({
      name: keyName,
      tags: { a: 'c' },
      metadata: 'updated metadata',
    })

    expect(key.jwkThumbprint === fetchedKey1?.key.jwkThumbprint).toBeTruthy()

    const found = await session.fetchAllKeys({
      algorithm: KeyAlgs.Ed25519,
      thumbprint: key.jwkThumbprint,
      tagFilter: { a: 'c' },
    })

    expect(found[0]).toMatchObject({ name: keyName, metadata: 'updated metadata', tags: { a: 'c' } })

    await session.removeKey({ name: keyName })

    await expect(session.fetchKey({ name: keyName })).resolves.toBeNull()

    await session.close()

    // Clear objects
    fetchedKey1?.key.handle.free()
    fetchedKey2?.key.handle.free()
    key.handle.free()
    found.forEach((entry) => entry.key.handle.free())
  })

  test('profile', async () => {
    const session = await store.openSession()
    await session.insert(firstEntry)
    await session.close()

    const profile = await store.createProfile()

    const session2 = await store.session(profile).open()
    //Should not find previously stored record
    await expect(session2.count(firstEntry)).resolves.toStrictEqual(0)
    await session2.insert(firstEntry)
    await expect(session2.count(firstEntry)).resolves.toStrictEqual(1)
    await session2.close()

    if (!store.uri.includes(':memory:')) {
      // Test accessing profile after re-opening
      const key = getRawKey()
      const store2 = await Store.open({ uri: testStoreUri, keyMethod: new StoreKeyMethod(KdfMethod.Raw), passKey: key })
      const session3 = await store2.openSession()
      //Should not find previously stored record
      await expect(session3.count(firstEntry)).resolves.toStrictEqual(0)
      await session3.close()
      await store2.close()
    }

    await expect(store.createProfile(profile)).rejects.toThrowError(AriesAskarError)

    // Check if profile is still usable
    const session4 = await store.session(profile).open()
    await expect(session4.count(firstEntry)).resolves.toStrictEqual(1)
    await session4.close()

    await store.removeProfile(profile)

    // Profile key is cached
    const session5 = await store.session(profile).open()
    await expect(session5.count(firstEntry)).resolves.toStrictEqual(0)
    await session5.close()

    // Unknown profile
    const session6 = await store.session('unknown profile').open()
    await expect(session6.count(firstEntry)).rejects.toThrowError(AriesAskarError)
    await session6.close()

    const session7 = await store.session(profile).open()
    await expect(session7.count(firstEntry)).resolves.toStrictEqual(0)
    await session7.close()
  })
})
