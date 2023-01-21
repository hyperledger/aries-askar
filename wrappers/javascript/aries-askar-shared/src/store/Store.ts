import type { StoreHandle } from '../crypto'
import type { StoreKeyMethod } from '../enums/StoreKeyMethod'

import { ariesAskar } from '../ariesAskar'

import { OpenSession } from './OpenSession'
import { Scan } from './Scan'

export class Store {
  private _handle: StoreHandle
  private _opener?: OpenSession
  private _uri: string

  public constructor({ handle, uri }: { handle: StoreHandle; uri: string }) {
    this._handle = handle
    this._uri = uri
  }

  public get handle() {
    return this._handle
  }

  public static generateRawKey(seed?: Uint8Array) {
    return ariesAskar.storeGenerateRawKey({ seed })
  }

  public get uri() {
    return this._uri
  }

  public async createProfile(name?: string) {
    return ariesAskar.storeCreateProfile({ storeHandle: this.handle, profile: name })
  }

  public async removeProfile(name: string) {
    return await ariesAskar.storeRemoveProfile({ profile: name, storeHandle: this.handle })
  }

  public async rekey({ keyMethod, passKey }: { keyMethod: StoreKeyMethod; passKey: string }) {
    return await ariesAskar.storeRekey({ keyMethod, passKey, storeHandle: this.handle })
  }

  public static async provision({
    uri,
    recreate,
    keyMethod,
    passKey,
    profile,
  }: {
    uri: string
    keyMethod?: StoreKeyMethod
    passKey?: string
    profile?: string
    recreate: boolean
  }) {
    const handle = await ariesAskar.storeProvision({ specUri: uri, keyMethod, profile, passKey, recreate })
    return new Store({ handle, uri })
  }

  public static async open({
    uri,
    keyMethod,
    passKey,
    profile,
  }: {
    uri: string
    keyMethod?: StoreKeyMethod
    passKey?: string
    profile?: string
  }) {
    const handle = await ariesAskar.storeOpen({ profile, passKey, keyMethod, specUri: uri })
    return new Store({ uri, handle })
  }

  public async close(remove = false) {
    this._opener = undefined

    if (this.handle) await this.handle.close()

    return remove ? await Store.remove(this.uri) : false
  }

  public static async remove(uri: string) {
    return await ariesAskar.storeRemove({ specUri: uri })
  }

  public session(profile?: string) {
    return new OpenSession({ store: this.handle, profile, isTxn: false })
  }

  public transaction(profile?: string) {
    return new OpenSession({ store: this.handle, profile, isTxn: true })
  }

  public async openSession(isTransaction = false) {
    this._opener ??= new OpenSession({ store: this.handle, isTxn: isTransaction })
    return await this._opener.open()
  }

  public scan(options: {
    category: string
    tagFilter?: Record<string, unknown>
    offset?: number
    limit?: number
    profile?: string
  }) {
    return new Scan({ ...options, store: this })
  }
}
