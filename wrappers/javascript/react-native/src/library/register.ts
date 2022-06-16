import type { AriesAskarNativeBindings } from 'aries-askar-shared'

// This can already check whether `_aries_askar` exists on global
// eslint-disable-next-line @typescript-eslint/no-use-before-define
if (!_aries_askar) {
  throw Error('_aries_askar has not been exposed on global. Something went wrong while installing the turboModule')
}

declare let _aries_askar: AriesAskarNativeBindings

export const ariesAskarReactNative = _aries_askar
