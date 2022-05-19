import type { EntryListHandle, ScanHandle } from '../crypto'
import type { Entry } from './Entry'
import type { Store } from './Store'

import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

import { EntryList } from './EntryList'

export class Scan {
  private _handle?: ScanHandle
  private _listHandle?: EntryListHandle
  private store?: Store
  private profile?: string
  private category: string
  private tagFilter?: Record<string, unknown>
  private offset?: number
  private limit?: number

  public constructor({
    category,
    limit,
    offset,
    profile,
    tagFilter,
  }: {
    profile?: string
    category: string
    tagFilter?: Record<string, unknown>
    offset?: number
    limit?: number
  }) {
    this.category = category
    this.profile = profile
    this.tagFilter = tagFilter
    this.offset = offset
    this.limit = limit
  }

  public get handle() {
    return this._handle
  }

  private async forEach(cb: (row: Entry, index?: number) => void) {
    if (!this.handle) {
      if (!this.store?.handle) throw new AriesAskarError({ code: 100, message: 'Cannot scan from closed store' })
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      this._handle = await ariesAskar.scanStart({
        storeHandle: this.store.handle,
        limit: this.limit,
        offset: this.offset,
        tagFilter: this.tagFilter,
        profile: this.profile,
        category: this.category,
      })

      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion, @typescript-eslint/no-unsafe-assignment
      this._listHandle = await ariesAskar.scanNext({ scanHandle: this._handle! })
    }
    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (!this._listHandle) break
      const list = new EntryList({ handle: this._listHandle })
      const entry = list.find(Boolean)
      if (entry) {
        cb(entry)
        break
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      this._listHandle = await ariesAskar.scanNext({ scanHandle: this._handle })
    }
  }

  public async fetchAll() {
    const rows: Array<Entry> = []
    await this.forEach((row) => rows.push(row))
    return rows
  }
}
