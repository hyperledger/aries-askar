import type { KeyEntryObject } from '.'
import type { KeyEntryListHandle } from '../crypto'

import { ariesAskar } from '../ariesAskar'

import { KeyEntry } from './KeyEntry'

export class KeyEntryList {
  private _handle: KeyEntryListHandle
  private _len = 0

  public constructor({ handle }: { handle: KeyEntryListHandle }) {
    this._handle = handle
    this._len = ariesAskar.keyEntryListCount({ keyEntryListHandle: handle })
  }

  public get handle() {
    return this._handle
  }

  public get length() {
    return this._len
  }

  public getEntryByIndex(index: number) {
    return new KeyEntry({ list: this.handle, pos: index })
  }

  public forEach(cb: (entry: KeyEntry, index?: number) => unknown) {
    for (let i = 0; i < this.length; i++) {
      cb(this.getEntryByIndex(i), i)
    }
  }

  public toArray(): Array<KeyEntryObject> {
    const list: Array<KeyEntryObject> = []
    this.forEach((key) => list.push(key.toJson()))
    return list
  }
}
