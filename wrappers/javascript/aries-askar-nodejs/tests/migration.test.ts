import { Migration } from '@hyperledger/aries-askar-shared'
import fs from 'fs'
import path from 'path'

const DB_TEMPLATE_PATH = path.join(__dirname, 'indy_wallet_sqlite.db')
const DB_UPGRADE_PATH = path.join(__dirname, 'indy_wallet_sqlite_upgraded.db')

describe('migration', () => {
  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  beforeEach(() => {
    const tplPaths = [DB_TEMPLATE_PATH, `${DB_TEMPLATE_PATH}-shm`, `${DB_TEMPLATE_PATH}-wal`]

    const updPaths = [DB_UPGRADE_PATH, `${DB_UPGRADE_PATH}-shm`, `${DB_UPGRADE_PATH}-wal`]

    for (let i = 0; i <= 3; i++) {
      const tplPath = tplPaths[i]
      const updPath = updPaths[i]

      if (fs.existsSync(tplPath)) {
        fs.copyFileSync(tplPath, updPath)
      } else {
        fs.existsSync(updPath) && fs.rmSync(updPath)
      }
    }
  })

  test('migrate', async () => {
    await expect(
      Migration.migrate({
        specUri: DB_UPGRADE_PATH,
        kdfLevel: 'RAW',
        walletName: 'walletwallet.0',
        walletKey: 'GfwU1DC7gEZNs3w41tjBiZYj7BNToDoFEqKY6wZXqs1A',
      })
    ).resolves.toBeUndefined()

    // Double migrate should not work
    await expect(
      Migration.migrate({
        specUri: DB_UPGRADE_PATH,
        kdfLevel: 'RAW',
        walletName: 'walletwallet.0',
        walletKey: 'GfwU1DC7gEZNs3w41tjBiZYj7BNToDoFEqKY6wZXqs1A',
      })
    ).rejects.toThrowError('Database is already migrated')
  })
})
