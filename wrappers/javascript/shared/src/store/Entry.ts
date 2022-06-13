import type { EntryListHandle } from '../crypto'

export class Entry {
  private _list: EntryListHandle
  private _pos: number
  private _keys = ['name', 'category', 'value', 'tags'] as const

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
    return this.rawValue
  }

  private get rawValue() {
    return this._list.getValue(this._pos)
  }

  public get tags() {
    return JSON.parse(this._list.getTags(this._pos)) as Record<string, unknown>
  }

  public get keys() {
    return this._keys
  }

  public toJson() {
    return {
      name: this.name,
      value: JSON.parse(this.value) as Record<string, unknown>,
      keys: this.keys,
      tags: this.tags,
      category: this.category,
    }
  }
}
