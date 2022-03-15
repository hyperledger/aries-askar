import { NativeModules, Platform } from 'react-native';
const LINKING_ERROR = `The package 'react-native-aries-askar' doesn't seem to be linked. Make sure: \n\n` + Platform.select({
  ios: "- You have run 'pod install'\n",
  default: ''
}) + '- You rebuilt the app after installing the package\n' + '- You are not using Expo managed workflow\n';
const AriesAskar = NativeModules.AriesAskar ? NativeModules.AriesAskar : new Proxy({}, {
  get() {
    throw new Error(LINKING_ERROR);
  }

});
export function multiply(a, b) {
  return AriesAskar.multiply(a, b);
}
//# sourceMappingURL=index.js.map