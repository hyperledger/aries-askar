import { registerAriesAskar } from 'aries-askar-shared'

import { NodeJSAriesAskar } from '../src'

describe('jose ecdh', () => {
  beforeAll(() => {
    registerAriesAskar({ askar: new NodeJSAriesAskar() })
  })
  test('ecdh es direct', () => {
    // const bobKey = Key.generate(KeyAlgs.EcSecp256r1)
    // const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1)
    // const message = Buffer.from('Hello there')
    // const apu = 'Alice'
    // const apv = 'Bob'
    // const enc = 'A256GCM'

    // const encryptedMessage = new EcdhEs({ apv, apu, algId: enc }).encryptDirect({
    //   encAlg: KeyAlgs.AesA256Gcm,
    //   ephemeralKey,
    //   message,
    //   receiverKey: bobKey,
    // })

    console.log('TODO')
  })
})
