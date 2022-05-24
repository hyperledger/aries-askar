// TODO: move this to nodejs?

import { ariesAskar } from '../ariesAskar'

export class ArcHandle {
  public handle: Buffer

  public constructor(handle: Buffer) {
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
    throw new Error('Method `close` not implemented!')
  }
}

export class SessionHandle {
  public handle: number

  public constructor(handle: number) {
    this.handle = handle
  }

  public close(commit: boolean) {
    throw new Error('Method `close` not implemented!')
  }
}

export class EntryListHandle extends ArcHandle {
  public getCategory(index: number) {
    return ariesAskar.entryListGetCategory({ index, entryListHandle: this })
  }

  public getName(index: number) {
    throw new Error('Method `getName` not implemented!')
  }

  public getValue(index: number) {
    throw new Error('Method `getValue` not implemented!')
  }

  public getTags(index: number) {
    throw new Error('Method `getTags` not implemented!')
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
