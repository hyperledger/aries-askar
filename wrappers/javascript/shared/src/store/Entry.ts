import type { EntryListHandle } from '../crypto'

export type EntryObject = {
  name: string
  value: Record<string, unknown> | string
  tags: Record<string, unknown>
  category: string
}

export class Entry {
  private _list: EntryListHandle
  private _position: number

  public constructor({ list, position }: { list: EntryListHandle; position: number }) {
    this._list = list
    this._position = position
  }

  public get category() {
    return this._list.getCategory(this._position)
  }

  public get name() {
    return this._list.getName(this._position)
  }

  public get value() {
    return this.rawValue
  }

  private get rawValue() {
    return this._list.getValue(this._position)
  }

  public get tags() {
    return JSON.parse(this._list.getTags(this._position)) as Record<string, unknown>
  }

  public toJson(shouldParseValueToJson = false): EntryObject {
    return {
      name: this.name,
      value: shouldParseValueToJson ? (JSON.parse(this.value) as Record<string, unknown>) : this.value,
      tags: this.tags,
      category: this.category,
    }
  }
}
