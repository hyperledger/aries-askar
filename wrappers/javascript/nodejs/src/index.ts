/* eslint-disable no-console */

import { NodeJSAriesAskar } from './ariesAskar'

const ariesAskarNodeJS = new NodeJSAriesAskar()

// TODO: lets test this btch (generate key and check how python initializes a store)
const run = () => {
  const seed = new Uint8Array(32).fill(20)
  ariesAskarNodeJS.setCustomLogger({ logLevel: 5, enabled: true, flush: true })
  ariesAskarNodeJS.keyFromSeed({ alg: 'ed25519', seed, method: '' })
}

void run()
