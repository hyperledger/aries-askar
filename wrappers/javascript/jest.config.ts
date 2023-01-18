import type { Config } from '@jest/types'

import base from './jest.config.base'

const config: Config.InitialOptions = {
  ...base,
  roots: ['<rootDir>'],
  projects: ['<rootDir>/*/jest.config.ts'],
}

export default config
