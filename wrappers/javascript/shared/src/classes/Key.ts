import type { KeyAlgs } from '../KeyAlgs'
import type { LocalKeyHandle } from './handles'

import { ariesAskar } from '../ariesAskar'

export class Key {
  private handle: LocalKeyHandle

  public constructor(handle: LocalKeyHandle) {
    this.handle = handle
  }

  public generate(alg: KeyAlgs, ephemeral = false) {
    const handle = ariesAskar.keyGenerate({ alg, ephemeral })
    return new Key(handle)
  }
}
