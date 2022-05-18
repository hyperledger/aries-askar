/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import { KeyAlgs, registerAriesAskar, Key, KeyMethod, ariesAskar } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

registerAriesAskar({ askar: new NodeJSAriesAskar() })

const run = () => {
  // const message = new Uint8Array(32).fill(10)
  const seed = new Uint8Array(32).fill(20)
  ariesAskar.setCustomLogger({ logLevel: 5 })
  const edKey = Key.fromSeed({ alg: KeyAlgs.Ed25519, seed, method: KeyMethod.BlsKeygen })
  // const signature = edKey.signMessage(message, SigAlgs.EdDSA)
  // console.log(edKey.verifyMessage(message, signature, SigAlgs.EdDSA))
  console.log(edKey.convertkey({ alg: KeyAlgs.X25519 }))
  // console.log(ariesAskarNodeJS.keyGetAlgorithm({ localKeyHandle: a128kw.handle }))
}

void run()
