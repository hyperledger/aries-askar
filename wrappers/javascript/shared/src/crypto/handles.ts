// TODO: do we need these classes?
import { ariesAskar } from '../ariesAskar'

export class ArcHandle {
  public handle: Uint8Array

  public constructor(handle: Uint8Array) {
    this.handle = handle
  }
}

export class StoreHandle {
  public handle: number

  public constructor(handle: number) {
    this.handle = handle
  }

  public async close() {
    await ariesAskar.storeClose({ storeHandle: this })
  }
}

export class ScanHandle {
  public handle: number

  public constructor(handle: number) {
    this.handle = handle
  }

  public free() {
    ariesAskar.scanFree({ scanHandle: this })
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
    return ariesAskar.keyEntryListGetAlgorithm({ index, keyEntryListHandle: this })
  }

  public getName(index: number) {
    return ariesAskar.keyEntryListGetName({ index, keyEntryListHandle: this })
  }

  public getTags(index: number) {
    return ariesAskar.keyEntryListGetTags({ index, keyEntryListHandle: this })
  }

  public getMetadata(index: number) {
    return ariesAskar.keyEntryListGetMetadata({ index, keyEntryListHandle: this })
  }

  public loadKey(index: number) {
    return ariesAskar.keyEntryListLoadLocal({ index, keyEntryListHandle: this })
  }
}

export class LocalKeyHandle extends ArcHandle {}
