export type AriesAskarErrorObject = {
  code: number
  message: string | null
}

export class AriesAskarError extends Error {
  public readonly code: number

  public constructor({ code, message }: AriesAskarErrorObject) {
    super(message ?? 'No message provided from Aries Askar')
    this.code = code
  }

  public static customError({ message }: { message: string }) {
    return new AriesAskarError({ message, code: 100 })
  }
}

export function handleInvalidNullResponse<T extends null | unknown>(response: T): Exclude<T, null> {
  if (response === null) {
    throw AriesAskarError.customError({ message: 'Invalid response. Expected value but received null pointer' })
  }

  return response as Exclude<T, null>
}
