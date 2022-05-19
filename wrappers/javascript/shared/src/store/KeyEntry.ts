import type { KeyEntryListHandle } from '../crypto'

export class KeyEntry {
  private _list: KeyEntryListHandle
  private _pos: number

  // TODO: what is pos
  public constructor({ list, pos }: { list: KeyEntryListHandle; pos: number }) {
    this._list = list
    this._pos = pos
  }

  public get algorithm() {
    return this._list.getAlgorithm(this._pos)
  }

  public get name() {
    return this._list.getName(this._pos)
  }

  public get metadata() {
    return this._list.getMetadata(this._pos)
  }

  public get tags() {
    return this._list.getTags(this._pos)
  }

  public get key() {
    return this._list.loadKey(this._pos)
  }
}
