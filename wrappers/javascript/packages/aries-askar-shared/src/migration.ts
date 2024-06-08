import { ariesAskar } from './ariesAskar'

type MigrationOptions = {
  walletName: string
  walletKey: string
  specUri: string
  kdfLevel: string
}

export class Migration {
  public static async migrate(options: MigrationOptions): Promise<void> {
    await ariesAskar.migrateIndySdk(options)
  }
}
