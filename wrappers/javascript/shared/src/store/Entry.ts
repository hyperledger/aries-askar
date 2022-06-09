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

  public get rawValue() {
    return this._list.getValue(this._pos)
  }

  public get jsonValue() {
    // return JSON.parse(this.rawValue) as Record<string, unknown>
    return {}
  }

  public get tags() {
    return JSON.parse(this._list.getTags(this._pos)) as Record<string, unknown>
  }

  public get keys() {
    return this._keys
  }

  public toJson() {
    const json = {
      name: this.name,
      value: this.value,
      keys: this.keys,
      tags: this.tags,
      jsonValue: this.jsonValue,
      category: this.category,
    }
    return json
  }
}
