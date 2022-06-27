import {CryptoBox, Key, KeyAlgs} from 'aries-askar-shared';

export const cryptoBoxSeal = () => {
  const x25519Key = Key.generate(KeyAlgs.X25519);

  // equal to: const message = Uint8Array.from(Buffer.from('foobar'));
  const message = new Uint8Array([102, 111, 111, 98, 97, 114]);
  const sealed = CryptoBox.seal({recipientKey: x25519Key, message});

  const opened = CryptoBox.sealOpen({
    recipientKey: x25519Key,
    ciphertext: sealed,
  });

  if (!message.every((v, i) => opened[i] === v)) {
    return 1;
  }
};
