import type { StoreHandle } from '../crypto'

import { ariesAskar } from '../ariesAskar'
import { AriesAskarError } from '../error'

import { Session } from './Session'

export class OpenSession {
  private store: StoreHandle
  private profile?: string
  private isTxn: boolean
  // TODO: implement session
  private session?: Session

  public constructor({ store, isTxn, profile }: { store: StoreHandle; profile?: string; isTxn: boolean }) {
    this.store = store
    this.isTxn = isTxn
    this.profile = profile
  }

  public async open() {
    if (!this.store) throw AriesAskarError.customError({ message: 'Cannot start session from closed store' })
    if (this.session) throw AriesAskarError.customError({ message: 'Session already opened' })
    const sessionHandle = await ariesAskar.sessionStart({
      profile: this.profile,
      asTransaction: this.isTxn,
      storeHandle: this.store,
    })
    return new Session({ isTxn: this.isTxn, handle: sessionHandle })
  }
}
