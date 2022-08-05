import type { EntryObject } from '.'
import type { EntryListHandle } from '../crypto'

import { ariesAskar } from '../ariesAskar'

import { Entry } from './Entry'

export class EntryList {
  private _handle: EntryListHandle
  private _length = 0

  public constructor({ handle, length }: { handle: EntryListHandle; length?: number }) {
    this._handle = handle
    this._length = length || ariesAskar.entryListCount({ entryListHandle: handle })
  }

  public get handle() {
    return this._handle
  }

  public get length() {
    return this._length
  }

  public getEntryByIndex(index: number) {
    return new Entry({ list: this.handle, position: index })
  }

  private forEach(cb: (entry: Entry, index?: number) => unknown) {
    for (let i = 0; i < this.length; i++) {
      cb(this.getEntryByIndex(i), i)
    }
  }

  public find(cb: (entry: Entry, index?: number) => boolean): Entry | undefined {
    for (let i = 0; i < this.length; i++) {
      const item = this.getEntryByIndex(i)
      if (cb(item)) return item
    }
  }

  public toArray(): Array<EntryObject> {
    const list: Array<EntryObject> = []
    this.forEach((entry) => list.push(entry.toJson()))
    return list
  }
}
