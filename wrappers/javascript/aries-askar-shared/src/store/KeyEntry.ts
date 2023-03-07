import type { KeyEntryListHandle } from '../crypto'

import { Key } from '../crypto'

export type KeyEntryObject = {
  algorithm: string
  name: string
  metadata: string | null
  tags: Record<string, unknown>
  key: Key
}

export class KeyEntry {
  private _list: KeyEntryListHandle
  private _pos: number

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
    const metadata = this._list.getMetadata(this._pos)

    return metadata
  }

  public get tags() {
    const tags = this._list.getTags(this._pos)

    if (!tags) return {}
    return JSON.parse(tags) as Record<string, unknown>
  }

  public get key() {
    return new Key(this._list.loadKey(this._pos))
  }

  public toJson(): KeyEntryObject {
    return {
      algorithm: this.algorithm,
      name: this.name,
      metadata: this.metadata,
      tags: this.tags,
      key: this.key,
    }
  }
}
