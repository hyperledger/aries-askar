import { AriesAskarError } from '../error'

export enum KeyBackend {
  Software = 'software',
  SecureElement = 'secure_element',
}

export const keyBackendFromString = (backend: string): KeyBackend => {
  const keyAlg = Object.entries(KeyBackend).find(([, value]) => value === backend)
  if (keyAlg) return keyAlg[1]

  throw AriesAskarError.customError({ message: `backend: ${backend} is not supported!` })
}

export const keyBackendToString = (alg: KeyBackend): string => {
  const keyAlg = Object.entries(KeyBackend).find(([key]) => key === alg)
  if (keyAlg) return keyAlg[0]

  throw AriesAskarError.customError({ message: `backend: ${alg} is not supported!` })
}
