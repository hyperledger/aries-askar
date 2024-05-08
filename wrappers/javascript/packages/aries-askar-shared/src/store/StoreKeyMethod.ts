export enum KdfMethod {
  Raw = 'raw',
  None = 'none',
  Argon2IMod = 'kdf:argon2i:mod',
  Argon2IInt = 'kdf:argon2i:int',
}

export class StoreKeyMethod {
  private method: KdfMethod

  public constructor(method: KdfMethod) {
    this.method = method
  }

  public toUri() {
    return this.method.toString()
  }
}
