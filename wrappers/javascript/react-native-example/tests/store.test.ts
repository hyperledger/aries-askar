import {Store, StoreKeyMethod} from 'aries-askar-shared';
import {firstEntry, secondEntry} from './fixtures';

const getRawKey = Store.generateRawKey;

export const setupStore = async () => {
  const key = getRawKey();
  return await Store.provision({
    recreate: true,
    uri: 'sqlite://:memory:',
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  });
};

export const storeInsert = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  if ((await session.count(firstEntry)) !== 1) {
    return 1;
  }

  await session.close();
};

export const storeReplace = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  if ((await session.count(firstEntry)) !== 1) {
    return 1;
  }
  const updatedEntry = {...firstEntry, value: 'bar', tags: {update: 'baz'}};
  await session.replace(updatedEntry);
  if ((await session.count(firstEntry)) !== 1) {
    return 1;
  }

  await session.close();
};

export const storeRemove = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  if ((await session.count(firstEntry)) !== 1) {
    return 1;
  }
  await session.remove(firstEntry);
  if ((await session.count(firstEntry)) !== 0) {
    return 1;
  }

  await session.close();
};

export const storeRemoveAll = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  await session.insert(secondEntry);
  if ((await session.count(firstEntry)) !== 2) {
    return 1;
  }
  await session.removeAll({category: firstEntry.category});
  if ((await session.count(firstEntry)) !== 0) {
    return 1;
  }

  await session.close();
};

export const storeScan = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  const found = await store.scan(firstEntry).fetchAll();

  if (found.length !== 1) {
    return 1;
  }

  await session.close();
};

export const storeTransactionBasic = async (store: Store) => {
  const txn = await store.openSession(true);
  await txn.insert(firstEntry);

  if ((await txn.count(firstEntry)) !== 1) {
    console.error('1');
    return 1;
  }

  if (!(await txn.fetch(firstEntry))) {
    console.error('2');
    return 1;
  }

  const found = await txn.fetchAll(firstEntry);

  if (found.length !== 1) {
    return 1;
  }

  await txn.commit();

  await txn.close();

  const session = await store.openSession();

  if (!(await session.fetch(firstEntry))) {
    return 1;
  }

  await session.close();
};

export const storeProfile = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  await session.close();

  const profile = await store.createProfile();

  const session2 = await store.session(profile).open();
  //Should not find previously stored record
  if ((await session2.count(firstEntry)) !== 0) {
    return 1;
  }
  await session2.insert(firstEntry);
  if ((await session2.count(firstEntry)) !== 1) {
    return 1;
  }
  await session2.close();

  try {
    await store.createProfile(profile);
    return 1;
  } catch (e) {}

  const session3 = await store.session(profile).open();
  if ((await session3.count(firstEntry)) !== 1) {
    return 1;
  }
  await session3.close();

  await store.removeProfile(profile);

  const session4 = await store.session(profile).open();
  if ((await session4.count(firstEntry)) !== 0) {
    return 1;
  }
  await session4.close();

  const session5 = await store.session('unknown profile').open();
  try {
    await session5.count(firstEntry);
    return 1;
  } catch (e) {}
  await session5.close();

  const session6 = await store.session(profile).open();
  if ((await session6.count(firstEntry)) !== 0) {
    return 1;
  }
  await session6.close();
};
