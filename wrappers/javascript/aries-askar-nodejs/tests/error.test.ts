import { AriesAskarError, KeyAlgs, ariesAskar } from '@hyperledger/aries-askar-shared'

import { setupWallet } from './utils'

describe('Error', () => {
  beforeAll(() => {
    require('@hyperledger/aries-askar-nodejs')
  })

  test('set error code to 0 after correct call', () => {
    expect(() =>
      ariesAskar.keyGenerate({
        algorithm: KeyAlgs.AesA128CbcHs256,
        ephemeral: true,
      })
    ).not.toThrowError()
  })

  test('set error code to non 0 after incorrect call', () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    expect(() => ariesAskar.keyGenerate({ algorithm: 'incorrect-alg', ephemeral: true })).toThrowError(
      new AriesAskarError({ code: 1, message: 'Unknown key algorithm' })
    )
  })

  test('set error code to 0 correct async call', async () => {
    const store = await setupWallet()

    await expect(store.openSession()).resolves.toBeTruthy()
  })

  test('set error code to non 0 incorrect async call where the error is outside the callback', async () => {
    const store = await setupWallet()

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    await expect(store.removeProfile()).rejects.toMatchObject({
      code: 5,
      message: 'Profile name not provided',
    })
  })

  test('set error code to non 0 incorrect async call where the error is inside the callback', async () => {
    const store = await setupWallet()
    await store.close()

    await expect(store.close()).rejects.toMatchObject({
      code: 5,
      message: 'Invalid store handle',
    })
  })
})
