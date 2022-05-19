import type { EntryListHandle } from '../crypto'

export class Entry {
  private _list: EntryListHandle
  private _pos: number
  private _keys = ['name', 'category', 'value', 'tags'] as const

  // TODO: what is pos
  public constructor({ list, pos }: { list: EntryListHandle; pos: number }) {
    this._list = list
    this._pos = pos
  }

  public get category() {
    return this._list.getCategory(this._pos)
  }

  public get name() {
    return this._list.getName(this._pos)
  }

  public get value() {
    // TODO: fix return type for list.getValue
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    return new Uint8Array(this.rawValue)
  }

  public get rawValue() {
    return this._list.getValue(this._pos)
  }

  public get jsonValue() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return JSON.parse(this.rawValue)
  }

  public get tags() {
    return this._list.getTags(this._pos)
  }

  public get keys() {
    return this._keys
  }
}
