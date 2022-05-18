/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import { KeyAlgs, registerAriesAskar, Key, SigAlgs } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

const ariesAskarNodeJS = new NodeJSAriesAskar()

registerAriesAskar({ askar: ariesAskarNodeJS })

const run = () => {
  const message = new Uint8Array(32).fill(10)
  const seed = new Uint8Array(32).fill(20)
  ariesAskarNodeJS.setCustomLogger({ logLevel: 5, enabled: true, flush: true })
  const edKey = Key.fromSeed(KeyAlgs.Ed25519, seed)
  const signature = edKey.signMessage(message, SigAlgs.EdDSA)
  console.log(signature)
  // Why does this respond with 0
  console.log(edKey.verifyMessage(message, signature, SigAlgs.EdDSA))
  // const a128kw = ariesAskarNodeJS.keyFromSeed({ alg: KeyAlgs.AesA128Kw, seed, method: '' })
  // console.log(ariesAskarNodeJS.keyGetAlgorithm({ localKeyHandle: a128kw.handle }))
}

void run()
