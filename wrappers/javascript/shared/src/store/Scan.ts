import type { EntryListHandle, ScanHandle } from '../crypto'
import type { Entry, EntryObject } from './Entry'
import type { Store } from './Store'

import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

import { EntryList } from './EntryList'

export class Scan {
  private _handle?: ScanHandle
  private _listHandle?: EntryListHandle
  private store: Store
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
    store,
  }: {
    profile?: string
    category: string
    tagFilter?: Record<string, unknown>
    offset?: number
    limit?: number
    store: Store
  }) {
    this.category = category
    this.profile = profile
    this.tagFilter = tagFilter
    this.offset = offset
    this.limit = limit
    this.store = store
  }

  public get handle() {
    return this._handle
  }

  private async forEach(cb: (row: Entry, index?: number) => void) {
    if (!this.handle) {
      if (!this.store?.handle) throw AriesAskarError.customError({ message: 'Cannot scan from closed store' })
      this._handle = await ariesAskar.scanStart({
        storeHandle: this.store.handle,
        limit: this.limit,
        offset: this.offset,
        tagFilter: this.tagFilter,
        profile: this.profile,
        category: this.category,
      })

      this._listHandle = await ariesAskar.scanNext({ scanHandle: this._handle })
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
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      this._listHandle = await ariesAskar.scanNext({ scanHandle: this._handle! })
    }
  }

  public async fetchAll() {
    const rows: Array<EntryObject> = []
    await this.forEach((row) => rows.push(row.toJson()))
    return rows
  }
}
