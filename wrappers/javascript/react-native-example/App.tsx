import React from 'react';
import {SafeAreaView} from 'react-native';
import {ReactNativeAriesAskar} from 'aries-askar-react-native';
import {registerAriesAskar, ariesAskar} from 'aries-askar-shared';

const func = async () => {
  const key = ariesAskar.storeGenerateRawKey({
    seed: new Uint8Array(32).fill(1),
  });
  const foo = await ariesAskar.storeProvision({
    specUri: 'sqlite://:memory:',
    keyMethod: 'raw',
    passKey: key,
    recreate: true,
  });
  return foo;
};

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});

  func().then(console.log).catch(console.error);

  return <SafeAreaView />;
};
