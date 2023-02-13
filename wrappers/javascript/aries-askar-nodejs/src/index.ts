import { registerAriesAskar } from '@hyperledger/aries-askar-shared'

import { NodeJSAriesAskar } from './NodeJSAriesAskar'

export const ariesAskarNodeJS = new NodeJSAriesAskar()
registerAriesAskar({ askar: ariesAskarNodeJS })

export * from '@hyperledger/aries-askar-shared'
