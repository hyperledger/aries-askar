import React from 'react';
import {SafeAreaView} from 'react-native';
import {ariesAskarReactNative} from 'aries-askar-react-native';

export const App = () => {
  console.log(ariesAskarReactNative.version({}));
  return <SafeAreaView />;
};
