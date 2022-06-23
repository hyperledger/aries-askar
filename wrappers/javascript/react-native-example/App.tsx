import React from 'react';
import {SafeAreaView} from 'react-native';
import {ReactNativeAriesAskar} from 'aries-askar-react-native';
import {registerAriesAskar, ariesAskar, StoreHandle} from 'aries-askar-shared';

const tryTest = async (cb: () => Promise<any>) => {
  try {
    await cb();
  } catch (e) {
    console.error(e);
  }
};

const startAndGetProfileName = async () => {
  const key = ariesAskar.storeGenerateRawKey({
    seed: new Uint8Array(32).fill(1),
  });
  const handle = await ariesAskar.storeProvision({
    specUri: 'sqlite://:memory:',
    keyMethod: 'raw',
    passKey: key,
    recreate: true,
  });
  const storeHandle = new StoreHandle(handle);

  const profileName = await ariesAskar.storeGetProfileName({storeHandle});

  if (!profileName) {
    throw new Error('No Profilename');
  }

  await storeHandle.close();
};

const startAndCloseStore = async () => {
  const key = ariesAskar.storeGenerateRawKey({
    seed: new Uint8Array(32).fill(1),
  });
  const handle = await ariesAskar.storeProvision({
    specUri: 'sqlite://:memory:',
    keyMethod: 'raw',
    passKey: key,
    recreate: true,
  });
  const storeHandle = new StoreHandle(handle);

  await storeHandle.close();
};

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});

  tryTest(startAndCloseStore);
  tryTest(startAndGetProfileName);

  return <SafeAreaView />;
};
