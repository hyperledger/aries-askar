import type { ReturnObject } from './serialize'
import type { AriesAskarErrorObject } from '@hyperledger/aries-askar-shared'

import { ariesAskar, AriesAskarError } from '@hyperledger/aries-askar-shared'

export const handleError = <T>({ errorCode, value }: ReturnObject<T>): T => {
  if (errorCode !== 0) {
    throw new AriesAskarError(JSON.parse(ariesAskar.getCurrentError()) as AriesAskarErrorObject)
  }

  return value as T
}
