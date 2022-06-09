// TODO: move this to nodejs?

import { ariesAskar } from '../ariesAskar'

export class ArcHandle {
  public handle: Uint8Array

  public constructor(handle: Uint8Array) {
    this.handle = handle
  }
}

// TOOD: this is a number
export class StoreHandle {
  public handle: number

  public constructor(handle: number) {
    this.handle = handle
  }

  public async close() {
    await ariesAskar.storeClose({ storeHandle: this })
  }
}

export class SessionHandle {
  public handle: number

  public constructor(handle: number) {
    this.handle = handle
  }

  public async close(commit: boolean) {
    await ariesAskar.sessionClose({ commit, sessionHandle: this })
  }
}

export class EntryListHandle extends ArcHandle {
  public getCategory(index: number) {
    return ariesAskar.entryListGetCategory({ index, entryListHandle: this })
  }

  public getName(index: number) {
    return ariesAskar.entryListGetName({ index, entryListHandle: this })
  }

  public getValue(index: number) {
    return ariesAskar.entryListGetValue({ index, entryListHandle: this })
  }

  public getTags(index: number) {
    return ariesAskar.entryListGetTags({ index, entryListHandle: this })
  }
}

export class KeyEntryListHandle extends ArcHandle {
  public getAlgorithm(index: number) {
    throw new Error('Method `getAlgorithm` not implemented!')
  }

  public getName(index: number) {
    throw new Error('Method `getName` not implemented!')
  }

  public getTags(index: number) {
    throw new Error('Method `getTags` not implemented!')
  }

  public getMetadata(index: number) {
    throw new Error('Method `getMetadata` not implemented!')
  }

  public loadKey(index: number) {
    throw new Error('Method `loadKey` not implemented!')
  }
}

export class ScanHandle extends ArcHandle {}

export class LocalKeyHandle extends ArcHandle {}
