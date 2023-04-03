import { AriesAskarError } from '../error'

export enum KdfMethod {
  Raw = 'raw',
  Kdf = 'kdf',
  None = 'none',
}

export enum Argon2Level {
  Interactive = 'int',
  Moderate = 'mod',
}

export class StoreKeyMethod {
  private method: KdfMethod
  private argon2Level?: Argon2Level

  public constructor(method: KdfMethod, argon2Level?: Argon2Level) {
    if (method == KdfMethod.Kdf && !argon2Level) {
      throw AriesAskarError.customError({ message: 'KDF method must be combined with an argon2 level' })
    }

    this.method = method
    this.argon2Level = argon2Level
  }

  public toUri() {
    switch (this.method) {
      case KdfMethod.None:
        return KdfMethod.None
      case KdfMethod.Raw:
        return KdfMethod.Raw
      case KdfMethod.Kdf:
        if (!this.argon2Level) {
          throw AriesAskarError.customError({ message: 'KDF method must be combined with argon2 level' })
        }

        // the details, aka "?salt=..." is omitted here.
        return `${KdfMethod.Kdf}:argon2i:${this.argon2Level}`
    }
  }
}
