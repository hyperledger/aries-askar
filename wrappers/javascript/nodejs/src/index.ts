/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import { KeyAlgs, registerAriesAskar } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

const ariesAskarNodeJS = new NodeJSAriesAskar()
registerAriesAskar({ askar: ariesAskarNodeJS })

const run = () => {
  const seed = new Uint8Array(32).fill(20)
  ariesAskarNodeJS.setCustomLogger({ logLevel: 5, enabled: true, flush: true })
  const a128kw = ariesAskarNodeJS.keyFromSeed({ alg: KeyAlgs.AesA128Kw, seed, method: '' })
  console.log(ariesAskarNodeJS.keyGetAlgorithm({ localkeyHandle: a128kw.handle }))
}

void run()
