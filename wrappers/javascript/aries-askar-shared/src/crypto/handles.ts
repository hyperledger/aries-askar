import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

type ArcHandleType = Uint8Array | string | null

export class ArcHandle {
  public handle: Uint8Array | string

  public constructor(handle: Uint8Array | string) {
    if (handle === '0') {
      throw AriesAskarError.customError({
        message: 'Invalid handle. This means that the function call succeeded but none was found.',
      })
    }
    this.handle = handle
  }

  public static fromHandle(handle: ArcHandleType) {
    return fromPointerHandle(this, handle)
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

  public static fromHandle(handle: number | null) {
    return fromSequenceHandle(this, handle)
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

  public static fromHandle(handle: number | null) {
    return fromSequenceHandle(this, handle)
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

  public static fromHandle(handle: number | null) {
    return fromSequenceHandle(this, handle)
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

  public free() {
    ariesAskar.entryListFree({ entryListHandle: this })
  }

  public static fromHandle(handle: ArcHandleType) {
    return fromPointerHandle(this, handle)
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

  public free() {
    ariesAskar.keyEntryListFree({ keyEntryListHandle: this })
  }

  public static fromHandle(handle: ArcHandleType) {
    return fromPointerHandle(this, handle)
  }
}

export class LocalKeyHandle extends ArcHandle {
  public free() {
    ariesAskar.keyFree({ localKeyHandle: this })
  }

  public static fromHandle(handle: ArcHandleType) {
    return fromPointerHandle(this, handle)
  }
}

/**
 * Instantiate an handle class based on a received handle. If the handle has a value
 * of null, the handle class won't be instantiated but rather null will be returned.
 */
function fromPointerHandle<HC extends typeof ArcHandle, H extends ArcHandleType>(
  HandleClass: HC,
  handle: H
): H extends null ? null : InstanceType<HC> {
  return (handle ? (new HandleClass(handle) as InstanceType<HC>) : null) as H extends null ? null : InstanceType<HC>
}

function fromSequenceHandle<
  HC extends typeof StoreHandle | typeof ScanHandle | typeof SessionHandle,
  H extends number | null
>(HandleClass: HC, handle: H): InstanceType<HC> {
  if (handle === null) {
    throw AriesAskarError.customError({ message: 'Invalid handle' })
  }

  return new HandleClass(handle) as InstanceType<HC>
}
