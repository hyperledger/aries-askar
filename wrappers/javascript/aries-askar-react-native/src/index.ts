import { registerAriesAskar } from '@hyperledger/aries-askar-shared'
import { NativeModules } from 'react-native'

import { ReactNativeAriesAskar } from './ReactNativeAriesAskar'

type Module = {
  install: () => boolean
}

const module = NativeModules.AriesAskar as Module
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

// Reexport everything from shared
export * from '@hyperledger/aries-askar-shared'

export const ariesAskarReactNative = new ReactNativeAriesAskar()

registerAriesAskar({ askar: ariesAskarReactNative })
