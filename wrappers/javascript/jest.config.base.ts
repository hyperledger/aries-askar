import type { Config } from '@jest/types'

const config: Config.InitialOptions = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  testMatch: ['**/?(*.)+(spec|test).[tj]s?(x)'],
  moduleNameMapper: {
    '@hyperledger/aries-askar-shared': ['<rootDir>/../aries-askar-shared/src'],
    '@hyperledger/aries-askar-nodejs': ['<rootDir>/src'],
  },
  globals: {
    'ts-jest': {
      isolatedModules: true,
    },
  },
}

export default config
