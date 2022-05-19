import type { StoreHandle } from '../crypto'
import type { KeyMethod } from '../enums'

import { ariesAskar } from '../ariesAskar'

export class Store {
  private _handle: StoreHandle
  // TODO: implement OpenSession
  private _opener?: string
  private _uri: string

  public constructor({ handle, uri }: { handle: StoreHandle; uri: string }) {
    this._handle = handle
    this._uri = uri
  }

  public get handle() {
    return this._handle
  }

  public generateRawKey(seed?: Uint8Array) {
    return ariesAskar.storeGenerateRawKey({ seed })
  }

  public uri() {
    return this._uri
  }

  public static async provision({
    uri,
    recreate,
    keyMethod,
    passKey,
    profile,
  }: {
    uri: string
    keyMethod?: KeyMethod
    passKey?: string
    profile?: string
    recreate: boolean
  }) {
    // TODO: why is this unsafe?
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const handle = await ariesAskar.storeProvision({ specUri: uri, keyMethod, profile, passKey, recreate })
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    return new Store({ handle, uri })
  }

  public static async open({
    uri,
    keyMethod,
    passKey,
    profile,
  }: {
    uri: string
    keyMethod?: KeyMethod
    passKey?: string
    profile?: string
  }) {
    // TODO: why is this unsafe?
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const handle = await ariesAskar.storeOpen({ profile, passKey, keyMethod, specUri: uri })
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    return new Store({ uri, handle })
  }

  public async remove({ uri }: { uri: string }) {
    return await ariesAskar.storeRemove({ specUri: uri })
  }
}
