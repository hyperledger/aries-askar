/* eslint-disable no-console */

import { KeyAlgs } from 'aries-askar-shared'

import { NodeJSAriesAskar } from './ariesAskar'

const ariesAskarNodeJS = new NodeJSAriesAskar()

const run = () => {
  const seed = new Uint8Array(32).fill(20)
  ariesAskarNodeJS.setCustomLogger({ logLevel: 5, enabled: true, flush: true })
  // ariesAskarNodeJS.keyFromSeed({ alg: KeyAlgs.Ed25519, seed, method: '' })
  ariesAskarNodeJS.keyFromSeed({ alg: KeyAlgs.X25519, seed, method: '' })
}

void run()
