/* eslint-disable @typescript-eslint/no-unsafe-return */
import type { Key, SessionHandle, StoreHandle } from '../crypto'
import type { KeyAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'
import { EntryOperation } from '../enums/EntryOperation'
import { AriesAskarError } from '../error'

import { Entry } from './Entry'
import { EntryList } from './EntryList'
import { KeyEntryList } from './KeyEntryList'

export class Session {
  // TODO: where is the store used?
  private store: StoreHandle
  private _handle?: SessionHandle
  private isTxn: boolean

  public constructor({ store, handle, isTxn }: { store: StoreHandle; handle?: SessionHandle; isTxn: boolean }) {
    this.store = store
    this._handle = handle
    this.isTxn = isTxn
  }

  public get isTransaction() {
    return this.isTxn
  }

  public get handle() {
    return this._handle
  }

  public async count({ category, tagFilter }: { category: string; tagFilter?: Record<string, unknown> }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot count from closed session' })
    return await ariesAskar.sessionCount({ tagFilter, category, sessionHandle: this.handle })
  }

  public async fetch({
    category,
    name,
    forUpdate = false,
    isJson = false,
  }: {
    category: string
    name: string
    forUpdate?: boolean
    isJson?: boolean
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot fetch from a closed session' })

    const handle = await ariesAskar.sessionFetch({ forUpdate, name, category, sessionHandle: this.handle })
    if (!handle) return undefined

    const entry = new Entry({ list: handle, pos: 0 })
    // console.log(entry)

    return entry.toJson(isJson)
  }

  public async fetchAll({
    category,
    forUpdate = false,
    limit,
    tagFilter,
  }: {
    category: string
    tagFilter?: Record<string, unknown>
    limit?: number
    forUpdate?: boolean
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot fetch all from a closed session' })
    const handle = await ariesAskar.sessionFetchAll({
      forUpdate,
      limit,
      tagFilter,
      sessionHandle: this.handle,
      category,
    })
    return new EntryList({ handle })
  }

  public async insert({
    category,
    name,
    expiryMs,
    tags,
    value,
  }: {
    category: string
    name: string
    value: string | Record<string, unknown>
    tags?: Record<string, unknown>
    expiryMs?: number
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot insert with a closed session' })
    const serializedValue = JSON.stringify(value)
    if (!serializedValue)
      throw new AriesAskarError({ code: 100, message: 'Either `value` or `valueJson` must be defined' })

    // @ts-ignore
    const encoder = new TextEncoder()

    await ariesAskar.sessionUpdate({
      // @ts-ignore
      value: new Uint8Array(encoder.encode(serializedValue)),
      expiryMs,
      tags,
      name,
      category,
      sessionHandle: this.handle,
      operation: EntryOperation.Insert,
    })
  }

  public async replace({
    category,
    name,
    expiryMs,
    tags,
    value,
    valueJson,
  }: {
    category: string
    name: string
    value?: string
    tags?: Record<string, unknown>
    expiryMs?: number
    valueJson?: unknown
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot replace with a closed session' })
    const serializedValue = !value && valueJson ? JSON.stringify(valueJson) : value
    if (!serializedValue)
      throw new AriesAskarError({ code: 100, message: 'Either `value` or `valueJson` must be defined' })

    // @ts-ignore
    const encoder = new TextEncoder()

    await ariesAskar.sessionUpdate({
      // @ts-ignore
      value: new Uint8Array(encoder.encode(serializedValue)),
      expiryMs,
      tags,
      name,
      category,
      sessionHandle: this.handle,
      operation: EntryOperation.Replace,
    })
  }

  public async remove({ category, name }: { category: string; name: string }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot remove with a closed session' })

    await ariesAskar.sessionUpdate({
      name,
      category,
      sessionHandle: this.handle,
      operation: EntryOperation.Remove,
    })
  }

  public async removeAll({ category, tagFilter }: { category: string; tagFilter: Record<string, unknown> }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot remove all with a closed session' })

    await ariesAskar.sessionRemoveAll({
      category,
      sessionHandle: this.handle,
      tagFilter,
    })
  }

  public async insertKey({
    name,
    key,
    expiryMs,
    metadata,
    tags,
  }: {
    name: string
    key: Key
    metadata?: string
    tags?: string
    expiryMs?: number
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot insert a key with a closed session' })

    await ariesAskar.sessionInsertKey({
      expiryMs,
      tags,
      metadata,
      name,
      sessionHandle: this.handle,
      localKeyHandle: key.handle,
    })
  }

  public async fetchKey({ name, forUpdate }: { name: string; forUpdate: boolean }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot fetch a key with a closed session' })
    const handle = await ariesAskar.sessionFetchKey({ forUpdate, name, sessionHandle: this.handle })
    //TODO: what to return here
  }

  public async fetchAllKeys({
    forUpdate,
    alg,
    limit,
    tagFilter,
    thumbprint,
  }: {
    alg?: KeyAlgs
    thumbprint?: string
    tagFilter?: Record<string, unknown>
    limit?: number
    forUpdate: boolean
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot fetch all keys with a closed session' })
    const handle = await ariesAskar.sessionFetchAllKeys({
      forUpdate,
      limit,
      tagFilter,
      thumbprint,
      alg,
      sessionHandle: this.handle,
    })

    return new KeyEntryList({ handle })
  }

  public async updateKey({
    name,
    expiryMs,
    metadata,
    tags,
  }: {
    name: string
    metadata?: string
    tags?: Record<string, unknown>
    expiryMs?: number
  }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot update a key with a closed session' })
    await ariesAskar.sessionUpdateKey({ expiryMs, tags, metadata, name, sessionHandle: this.handle })
  }

  public async removeKey({ name }: { name: string }) {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot remove a key with a closed session' })
    await ariesAskar.sessionRemoveKey({ name, sessionHandle: this.handle })
  }

  public async commit() {
    if (!this.isTxn) throw new AriesAskarError({ code: 100, message: 'Session is not a transaction' })
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot commit a closed session' })
    await this.handle.close(true)
    this._handle = undefined
  }

  public async rollback() {
    if (!this.isTxn) throw new AriesAskarError({ code: 100, message: 'Session is not a transaction' })
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot rollback a closed session' })
    await this.handle.close(false)
    this._handle = undefined
  }

  public async close() {
    if (!this.handle) throw new AriesAskarError({ code: 100, message: 'Cannot close a closed session' })
    await this.handle.close(false)
    this._handle = undefined
  }
}
