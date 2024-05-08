import type { NativeBindings } from './NativeBindings'

import { registerAriesAskar } from '@hyperledger/aries-askar-shared'
import { NativeModules } from 'react-native'

import { ReactNativeAriesAskar } from './ReactNativeAriesAskar'

// Reexport everything from shared
export * from '@hyperledger/aries-askar-shared'

const module = NativeModules.AriesAskar as { install: () => boolean }
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

// This can already check whether `_aries_askar` exists on global
// eslint-disable-next-line @typescript-eslint/no-use-before-define
if (!_aries_askar) {
  throw Error('_aries_askar has not been exposed on global. Something went wrong while installing the turboModule')
}

declare let _aries_askar: NativeBindings

registerAriesAskar({ askar: new ReactNativeAriesAskar(_aries_askar) })
