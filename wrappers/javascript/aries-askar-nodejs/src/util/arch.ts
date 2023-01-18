/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable no-console */
import os from 'os'

// Find appropriate target architecture settings for retrieving askar binaries
const platform = os.platform()
const arch = os.arch()

const archTable: { [key: string]: string } = {
  x64: 'x86_64',
  arm64: 'aarch64',
}

const targetArchitecture = platform === 'darwin' ? 'universal' : archTable[arch]

if (targetArchitecture) {
  console.log(targetArchitecture)
}
