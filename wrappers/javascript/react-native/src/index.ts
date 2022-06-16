/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { NativeModules } from 'react-native'

import { ReactNativeAriesAskar } from './ReactNativeAriesAskar'

const module = NativeModules.AriesAskar
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

export const ariesAskarReactNative = new ReactNativeAriesAskar()
