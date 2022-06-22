import React from 'react';
import {SafeAreaView} from 'react-native';
import {
  ariesAskarReactNative,
  ReactNativeAriesAskar,
} from 'aries-askar-react-native';
import {registerAriesAskar} from 'aries-askar-shared';

export const App = () => {
  registerAriesAskar({askar: new ReactNativeAriesAskar()});
  console.log(ariesAskarReactNative.version({}));
  return <SafeAreaView />;
};
