/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { NativeModules } from 'react-native'

const module = NativeModules.AriesAskar
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

export { ReactNativeAriesAskar } from './ReactNativeAriesAskar'
export { ariesAskarReactNative } from './library'
