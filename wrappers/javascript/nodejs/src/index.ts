/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable no-console */

import type { AesA128KwInner } from 'aries-askar-shared'

import { KeyAlgs } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

const ariesAskarNodeJS = new NodeJSAriesAskar()

const run = () => {
  const seed = new Uint8Array(32).fill(20)
  ariesAskarNodeJS.setCustomLogger({ logLevel: 5, enabled: true, flush: true })
  const a128kw = ariesAskarNodeJS.keyFromSeed<AesA128KwInner>({ alg: KeyAlgs.AesA128Kw, seed, method: '' })
  // @ts-ignore
  const alg = ariesAskarNodeJS.keyGetAlgorithm({ localkeyHandle: a128kw })
  console.log(alg)
}

void run()
