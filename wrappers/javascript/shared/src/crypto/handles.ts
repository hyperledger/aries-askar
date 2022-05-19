// TODO: move this to nodejs?

export class ArcHandle {
  public handle: Buffer

  public constructor(handle: Buffer) {
    this.handle = handle
  }
}

export class StoreHandle extends ArcHandle {
  public close() {
    throw new Error('Method `close` not implemented!')
  }
}

export class SessionHandle extends ArcHandle {
  public async close(commit: boolean) {
    throw new Error('Method `close` not implemented!')
  }
}

export class EntryListHandle extends ArcHandle {
  public getCategory(index: number) {
    throw new Error('Method `getCategory` not implemented!')
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
