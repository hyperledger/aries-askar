/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { NativeModules } from 'react-native'

type Module = {
  install: () => boolean
}

const module = NativeModules.AriesAskar as Module
if (!module.install()) throw Error('Unable to install the turboModule: ariesAskar')

// Reexport everything from shared
export * from 'aries-askar-shared'

export { ReactNativeAriesAskar } from './ReactNativeAriesAskar'
