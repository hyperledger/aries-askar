import type { Key } from './Key'

import { ariesAskar } from '../ariesAskar'

export class CryptoBox {
  public static randomNonce() {
    return ariesAskar.keyCryptoBoxRandomNonce()
  }

  public static cryptoBox({
    recipientKey,
    senderKey,
    message,
    nonce,
  }: {
    recipientKey: Key
    senderKey: Key
    message: Uint8Array
    nonce: Uint8Array
  }) {
    return ariesAskar.keyCryptoBox({ nonce, message, senderKey, recipientKey })
  }

  public static open({
    recipientKey,
    senderKey,
    message,
    nonce,
  }: {
    recipientKey: Key
    senderKey: Key
    message: Uint8Array
    nonce: Uint8Array
  }) {
    return ariesAskar.keyCryptoBoxOpen({ nonce, message, senderKey, recipientKey })
  }

  public static seal({ recipientKey, message }: { recipientKey: Key; message: Uint8Array }) {
    return ariesAskar.keyCryptoBoxSeal({ message, localKeyHandle: recipientKey.handle })
  }

  public static sealOpen({ recipientKey, ciphertext }: { recipientKey: Key; ciphertext: Uint8Array }) {
    return ariesAskar.keyCryptoBoxSealOpen({ ciphertext, localKeyHandle: recipientKey.handle })
  }
}
