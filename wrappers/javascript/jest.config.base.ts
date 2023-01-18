import type { Config } from '@jest/types'

const config: Config.InitialOptions = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  testMatch: ['**/?(*.)+(spec|test).[tj]s?(x)'],
  moduleNameMapper: {
    'aries-askar-shared': ['<rootDir>/../aries-askar-shared/src'],
  },
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
}

export default config
