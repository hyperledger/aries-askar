import React, {useEffect, useState} from 'react';
import {Button, SafeAreaView} from 'react-native';
import {ReactNativeAriesAskar} from 'aries-askar-react-native';
import {registerAriesAskar, Store, StoreKeyMethod} from 'aries-askar-shared';

const doTest = async (
  cb: (store: Store) => Promise<1 | undefined>,
  name: string,
) => {
  try {
    const store = await setupStore();
    const res = await cb(store);
    if (res) {
      console.error(`Test ${name} failed`);
    } else {
      console.log(`Test ${name} succeeded`);
    }
    store.close(true);
  } catch (e) {
    console.error(`Test ${name} failed with mesage: ${e}`);
  }
};

const firstEntry = {
  category: 'category-one',
  name: 'testEntry',
  value: 'foobar',
  tags: {'~plaintag': 'a', enctag: 'b'},
};

const secondEntry = {
  category: 'category-one',
  name: 'secondEntry',
  value: {foo: 'bar'},
  tags: {'~plaintag': 'a', enctag: 'b'},
};

const thirdEntry = {
  category: 'category-one',
  name: 'thirdEntry',
  value: {foo: 'baz'},
  tags: {'~plaintag': 'a', enctag: 'b'},
};

const getRawKey = Store.generateRawKey;

const setupStore = async () => {
  const key = getRawKey();
  return await Store.provision({
    recreate: true,
    uri: 'sqlite://:memory:',
    keyMethod: StoreKeyMethod.Raw,
    passKey: key,
  });
};

const storeInsert = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  if ((await session.count(firstEntry)) !== 1) {
    return 1;
  }

  await session.close();
};

const storeReplace = async (store: Store) => {
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

const storeRemove = async (store: Store) => {
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

const storeRemoveAll = async (store: Store) => {
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

const storeScan = async (store: Store) => {
  const session = await store.openSession();
  await session.insert(firstEntry);
  const found = await store.scan(firstEntry).fetchAll();

  if (found.length !== 1) {
    return 1;
  }

  await session.close();
};

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});

  const testCases: Record<string, (store: Store) => Promise<1 | undefined>> = {
    'Store: insert': storeInsert,
    'Store: replace': storeReplace,
    'Store: remove': storeRemove,
    'Store: remove all': storeRemoveAll,
    'Store: Scan': storeScan,
  };

  return (
    <SafeAreaView>
      <Button
        title="Store: All"
        onPress={() => {
          Object.entries(testCases).map(
            async ([funcName, cb]) => await doTest(cb, funcName),
          );
        }}
      />
      {Object.entries(testCases).map(([funcName, cb]) => (
        <Button
          title={funcName}
          onPress={() => doTest(cb, funcName)}
          key={funcName}
        />
      ))}
    </SafeAreaView>
  );
};
