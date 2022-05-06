import type { AriesAskarErrorObject } from 'aries-askar-shared'

import { AriesAskarError } from 'aries-askar-shared'

import { nativeAriesAskar } from './lib'
import { allocateStringBuffer } from './utils'

export const handleError = () => {
  const nativeError = allocateStringBuffer()
  nativeAriesAskar.askar_get_current_error(nativeError)

  // TODO
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument
  const ariesAskarErrorObject: AriesAskarErrorObject = JSON.parse(nativeError.deref())

  if (ariesAskarErrorObject.code === 0) return

  throw new AriesAskarError(ariesAskarErrorObject)
}
