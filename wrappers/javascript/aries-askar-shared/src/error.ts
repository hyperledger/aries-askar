export type AriesAskarErrorObject = {
  code: number
  extra?: string
  message: string
}

export class AriesAskarError extends Error {
  public readonly code: number
  public readonly extra?: string

  public constructor({ code, message, extra }: AriesAskarErrorObject) {
    super(message)
    this.code = code
    this.extra = extra
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
