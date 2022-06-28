/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */

import { registerAriesAskar } from 'aries-askar-shared'
import { NativeModules } from 'react-native'

import { ReactNativeAriesAskar } from './ReactNativeAriesAskar'

const module = NativeModules.AriesAskar
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

registerAriesAskar({ askar: new ReactNativeAriesAskar() })

// Reexport everything from shared
export * from 'aries-askar-shared'
// This does not need to be exported (for debug now only)
export { ariesAskarReactNative } from './library'
