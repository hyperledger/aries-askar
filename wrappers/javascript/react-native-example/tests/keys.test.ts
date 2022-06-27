import {Key, KeyAlgs} from 'aries-askar-shared';

export const keyBlsG2Keygen = () => {
  // equal to: const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'));
  const seed = new Uint8Array([
    116, 101, 115, 116, 115, 101, 101, 100, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49,
  ]);
  const key = Key.fromSeed({alg: KeyAlgs.Bls12381G2, seed});
  const jwkPublic = key.jwkPublic;

  if (jwkPublic.crv !== 'BLS12381_G2') {
    return 1;
  }
  if (jwkPublic.kty !== 'OKP') {
    return 1;
  }
  if (
    jwkPublic.x !==
    'lH6hIRPzjlKW6LvPm0sHqyEbGqf8ag7UWpA_GFfefwq_kzDXSHmls9Yoza_be23zEw-pSOmKI_MGR1DahBa7Jbho2BGwDNV_QmyhxMYBwTH12Ltk_GLyPD4AP6pQVgge'
  ) {
    return 1;
  }
};

export const keyBlsG1Keygen = () => {
  // equal to: const seed = Uint8Array.from(Buffer.from('testseed000000000000000000000001'));
  const seed = new Uint8Array([
    116, 101, 115, 116, 115, 101, 101, 100, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 49,
  ]);
  const key = Key.fromSeed({alg: KeyAlgs.Bls12381G1, seed});
  const jwkPublic = key.jwkPublic;

  if (jwkPublic.crv !== 'BLS12381_G1') {
    return 1;
  }
  if (jwkPublic.kty !== 'OKP') {
    return 1;
  }
  if (
    jwkPublic.x !==
    'hsjb9FSBUJXuB1fCluEcUBLeAPgIbnZGfxPKyeN3LVjQaKFWzXfNtMFAY8VL-eu-'
  ) {
    return 1;
  }
};

export const keyEd25519 = () => {
  // equal to: const message = Uint8Array.from(Buffer.from('test message'))
  const message = new Uint8Array([
    116, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101,
  ]);

  const key = Key.generate(KeyAlgs.Ed25519);
  if (key.algorithm !== KeyAlgs.Ed25519) {
    return 1;
  }

  const signature = key.signMessage({message});

  if (!key.verifySignature({message, signature})) {
    return 1;
  }

  const x25519Key = key.convertkey({alg: KeyAlgs.X25519});
  const x25519Key2 = Key.generate(KeyAlgs.X25519);

  const kex = x25519Key.keyFromKeyExchange({
    alg: KeyAlgs.Chacha20XC20P,
    publicKey: x25519Key2,
  });

  if (!(kex instanceof Key)) {
    return 1;
  }

  const jwkPublic = key.jwkPublic;
  const jwkSecret = key.jwkSecret;

  if (jwkPublic.kty !== 'OKP' || jwkPublic.crv !== 'Ed25519') {
    return 1;
  }

  if (jwkSecret.kty !== 'OKP' || jwkSecret.crv !== 'Ed25519') {
    return 1;
  }
};
