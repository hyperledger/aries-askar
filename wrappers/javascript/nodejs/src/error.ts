import type { AriesAskarErrorObject } from 'aries-askar-shared'

import { AriesAskarError } from 'aries-askar-shared'

import { nativeAriesAskar } from './lib'
import { allocateStringBuffer } from './utils'

export const handleError = () => {
  const nativeError = allocateStringBuffer()
  nativeAriesAskar.askar_get_current_error(nativeError)

  const ariesAskarErrorObject = JSON.parse(nativeError.deref() as string) as AriesAskarErrorObject

  if (ariesAskarErrorObject.code === 0) return

  throw new AriesAskarError(ariesAskarErrorObject)
}