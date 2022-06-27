import {Key, KeyAlgs} from 'aries-askar-shared';
import {Buffer} from 'buffer';

export const keysAesCbcHmac = () => {
  const key = Key.generate(KeyAlgs.AesA128CbcHs256);
  if (key.algorithm !== KeyAlgs.AesA128CbcHs256) {
    return 1;
  }

  const messageString = 'test message';
  const message = Uint8Array.from(Buffer.from(messageString));
  const aeadNonce = key.aeadRandomNonce;
  const params = key.aeadParams;
  if (params.nonceLength !== 16) {
    return 2;
  }
  if (params.tagLength !== 16) {
    return 3;
  }
  const enc = key.aeadEncrypt({message, nonce: aeadNonce});
  const dec = key.aeadDecrypt(enc.parts);
  expect(dec).toStrictEqual(message);

  if (!message.every((v, i) => dec[i] === v)) {
    return 4;
  }
};

export const keyBlsG2Keygen = () => {
  const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'));
  const key = Key.fromSeed({algorithm: KeyAlgs.Bls12381G2, seed});

  const jwkPublic = key.jwkPublic;

  if (jwkPublic.crv !== 'BLS12381_G2') {
    return 1;
  }
  if (jwkPublic.kty !== 'OKP') {
    return 2;
  }
  if (
    jwkPublic.x !==
    'lH6hIRPzjlKW6LvPm0sHqyEbGqf8ag7UWpA_GFfefwq_kzDXSHmls9Yoza_be23zEw-pSOmKI_MGR1DahBa7Jbho2BGwDNV_QmyhxMYBwTH12Ltk_GLyPD4AP6pQVgge'
  ) {
    return 3;
  }
};

export const keyBlsG1Keygen = () => {
  const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'));
  const key = Key.fromSeed({algorithm: KeyAlgs.Bls12381G1, seed});
  const jwkPublic = key.jwkPublic;

  if (
    jwkPublic.crv !== 'BLS12381_G1' &&
    jwkPublic.kty !== 'OKP' &&
    jwkPublic.x !==
      'hsjb9FSBUJXuB1fCluEcUBLeAPgIbnZGfxPKyeN3LVjQaKFWzXfNtMFAY8VL-eu-'
  ) {
    return 1;
  }
};

export const keyEd25519 = () => {
  const message = Uint8Array.from(Buffer.from('test message'));
  const key = Key.generate(KeyAlgs.Ed25519);
  if (key.algorithm !== KeyAlgs.Ed25519) {
    return 1;
  }

  const signature = key.signMessage({message});

  if (!key.verifySignature({message, signature})) {
    return 2;
  }

  const x25519Key = key.convertkey({algorithm: KeyAlgs.X25519});
  const x25519Key2 = Key.generate(KeyAlgs.X25519);

  const kex = x25519Key.keyFromKeyExchange({
    algorithm: KeyAlgs.Chacha20XC20P,
    publicKey: x25519Key2,
  });

  if (!(kex instanceof Key)) {
    return 3;
  }

  const jwkPublic = key.jwkPublic;
  const jwkSecret = key.jwkSecret;

  if (jwkPublic.kty !== 'OKP' && jwkPublic.crv !== 'Ed25519') {
    return 4;
  }

  if (jwkSecret.kty !== 'OKP' && jwkSecret.crv !== 'Ed25519') {
    return 5;
  }
};
