import type { StoreHandle } from '../crypto'

import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

export class OpenSession {
  private store: StoreHandle
  private profile?: string
  private isTxn: boolean
  // TODO: implement session
  private session?: string

  public constructor({ store, isTxn, profile }: { store: StoreHandle; profile?: string; isTxn: boolean }) {
    this.store = store
    this.isTxn = isTxn
    this.profile = profile
  }

  public async open() {
    if (!this.store) throw new AriesAskarError({ code: 100, message: 'Cannot start session  from closed store' })
    if (this.session) throw new AriesAskarError({ code: 100, message: 'Session already opened' })
    const sessionHandle = await ariesAskar.sessionStart({
      profile: this.profile,
      asTransaction: this.isTxn,
      storeHandle: this.store,
    })
    return new Promise((r) => r('foo'))
  }
}
