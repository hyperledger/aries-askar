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
import {keyBlsG1Keygen, keyBlsG2Keygen, keyEd25519} from './tests/keys.test';
import {cryptoBoxSeal} from './tests/cryptoBox.test';

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

  const keyTestCases: Record<string, () => any> = {
    'Key: BLS G2 Keygen': keyBlsG2Keygen,
    'Key: BLS G1 Keygen': keyBlsG1Keygen,
    'Key: Ed25519': keyEd25519,
  };

  const cryptoBoxTestCases: Record<string, () => any> = {
    'CryptoBox: seal': cryptoBoxSeal,
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
      <Button
        title="Key: All"
        onPress={() => {
          Object.entries(keyTestCases).map(
            async ([funcName, cb]) => await doTest(cb, funcName),
          );
        }}
      />
      <Button
        title="CryptoBox: All"
        onPress={() => {
          Object.entries(cryptoBoxTestCases).map(
            async ([funcName, cb]) => await doTest(cb, funcName),
          );
        }}
      />
      {Object.entries({
        ...storeTestCases,
        ...keyTestCases,
        ...cryptoBoxTestCases,
      }).map(([funcName, cb]) => (
        <Button
          title={funcName}
          onPress={() => doTest(cb, funcName)}
          key={funcName}
        />
      ))}
    </SafeAreaView>
  );
};
