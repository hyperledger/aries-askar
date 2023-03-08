import type { EntryListHandle } from '../crypto'

export type EntryObject = {
  name: string
  value: Record<string, unknown> | string
  tags: Record<string, unknown>
  category: string
}

export class Entry {
  private _list: EntryListHandle
  private _pos: number

  public constructor({ list, position }: { list: EntryListHandle; position: number }) {
    this._list = list
    this._pos = position
  }

  public get category() {
    return this._list.getCategory(this._pos)
  }

  public get name() {
    return this._list.getName(this._pos)
  }

  public get value(): string {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
    const decoder = new TextDecoder()
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    return decoder.decode(this.rawValue)
  }

  private get rawValue() {
    return this._list.getValue(this._pos)
  }

  public get tags() {
    const tags = this._list.getTags(this._pos)

    if (!tags) return {}
    return JSON.parse(tags) as Record<string, unknown>
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
