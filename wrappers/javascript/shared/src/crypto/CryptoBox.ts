import type { Key } from './Key'

import { ariesAskar } from '../ariesAskar'

export class CryptoBox {
  public static randomNonce() {
    return ariesAskar.keyCryptoBoxRandomNonce()
  }

  // TODO: what it do?
  public static cryptoBox({
    receiverKey,
    senderKey,
    message,
    nonce,
  }: {
    receiverKey: Key
    senderKey: Key
    message: Uint8Array
    nonce: Uint8Array
  }) {
    return ariesAskar.keyCryptoBox({ nonce, message, senderKey: senderKey.handle, recipKey: receiverKey.handle })
  }

  public static open({
    reciverKey,
    senderKey,
    message,
    nonce,
  }: {
    reciverKey: Key
    senderKey: Key
    message: Uint8Array
    nonce: Uint8Array
  }) {
    return ariesAskar.keyCryptoBoxOpen({ nonce, message, senderKey: senderKey.handle, recipKey: reciverKey.handle })
  }

  public static seal({ receiverKey, message }: { receiverKey: Key; message: Uint8Array }) {
    return ariesAskar.keyCryptoBoxSeal({ message, localKeyHandle: receiverKey.handle })
  }

  public static sealOpen({ receiverKey, ciphertext }: { receiverKey: Key; ciphertext: Uint8Array }) {
    return ariesAskar.keyCryptoBoxSealOpen({ ciphertext, localKeyHandle: receiverKey.handle })
  }
}
