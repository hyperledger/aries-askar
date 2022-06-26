import React from 'react';
import {Button, SafeAreaView} from 'react-native';
import {ReactNativeAriesAskar} from 'aries-askar-react-native';
import {registerAriesAskar, Store} from 'aries-askar-shared';
import {
  setupStore,
  storeInsert,
  storeProfile,
  storeRemove,
  storeRemoveAll,
  storeReplace,
  storeScan,
  storeTransactionBasic,
} from './tests/store.test';

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

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});

  const storeTestCases: Record<
    string,
    (store: Store) => Promise<1 | undefined>
  > = {
    'Store: insert': storeInsert,
    'Store: replace': storeReplace,
    'Store: remove': storeRemove,
    'Store: remove all': storeRemoveAll,
    'Store: Scan': storeScan,
    'Store: Transaction Basic': storeTransactionBasic,
    'Store: profile': storeProfile,
  };

  return (
    <SafeAreaView>
      <Button
        title="Store: All"
        onPress={() => {
          Object.entries(storeTestCases).map(
            async ([funcName, cb]) => await doTest(cb, funcName),
          );
        }}
      />
      {Object.entries(storeTestCases).map(([funcName, cb]) => (
        <Button
          title={funcName}
          onPress={() => doTest(cb, funcName)}
          key={funcName}
        />
      ))}
    </SafeAreaView>
  );
};
