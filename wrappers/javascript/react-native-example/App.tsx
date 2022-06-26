import React from 'react';
import {Button, SafeAreaView} from 'react-native';
import {ReactNativeAriesAskar} from 'aries-askar-react-native';
import {
  registerAriesAskar,
  ariesAskar,
  StoreHandle,
  Session,
} from 'aries-askar-shared';

const tryTest = async (cb: () => Promise<any>) => {
  try {
    await cb();
  } catch (e) {
    console.error(e);
  }
};

const startSession = async () => {
  const key = ariesAskar.storeGenerateRawKey({
    seed: new Uint8Array(32).fill(1),
  });
  const storeHandle = await ariesAskar.storeProvision({
    specUri: 'sqlite://:memory:',
    keyMethod: 'raw',
    passKey: key,
    recreate: true,
  });

  const sessionHandle = await ariesAskar.sessionStart({
    storeHandle,
    asTransaction: false,
  });

  const session = new Session({
    store: storeHandle,
    handle: sessionHandle,
    isTxn: false,
  });

  await session.insert({category: 'foo', name: 'bar', value: {foo: 'bar'}});
  console.log(
    await session.fetch({category: 'foo', name: 'bar', isJson: true}),
  );
};

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});

  return (
    <SafeAreaView>
      <Button title="foo" onPress={startSession} />
    </SafeAreaView>
  );
};
