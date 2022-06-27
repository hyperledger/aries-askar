import {CryptoBox, Key, KeyAlgs} from 'aries-askar-shared';
import {Buffer} from 'buffer';

export const cryptoBoxSeal = () => {
  const x25519Key = Key.generate(KeyAlgs.X25519);

  const message = Uint8Array.from(Buffer.from('foobar'));
  const sealed = CryptoBox.seal({recipientKey: x25519Key, message});

  const opened = CryptoBox.sealOpen({
    recipientKey: x25519Key,
    ciphertext: sealed,
  });

  if (!message.every((v, i) => opened[i] === v)) {
    return 1;
  }
};
