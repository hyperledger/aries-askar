import {Ecdh1PU, EcdhEs, Jwk, Key, KeyAlgs} from 'aries-askar-shared';
import {Buffer} from 'buffer';

const base64url = (str: string) => Buffer.from(str, 'base64');

export const joseEcdhEsDirect = () => {
  const bobKey = Key.generate(KeyAlgs.EcSecp256r1);
  const bobJwk = bobKey.jwkPublic;
  const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1);
  const ephemeralJwk = ephemeralKey.jwkPublic;
  // equal to: Uint8Array.from(Buffer.from("Hello there"))
  const message = new Uint8Array([
    72, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101,
  ]);
  const alg = 'ECDH-ES';
  const apu = 'Alice';
  const apv = 'Bob';
  const encAlg = KeyAlgs.AesA256Gcm;

  const protectedJson = {
    alg,
    enc: encAlg,
    apu: base64url(apu),
    apv: base64url(apv),
    epk: ephemeralKey,
  };
  const protectedB64 = base64url(JSON.stringify(protectedJson));

  const encryptedMessage = new EcdhEs({
    algId: Uint8Array.from(Buffer.from(encAlg)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).encryptDirect({
    encAlg,
    ephemeralKey,
    message,
    recipientKey: bobJwk,
    aad: Uint8Array.from(Buffer.from(protectedB64)),
  });

  const {nonce, tag, ciphertext} = encryptedMessage.parts;

  const messageReceived = new EcdhEs({
    algId: Uint8Array.from(Buffer.from(encAlg)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).decryptDirect({
    encAlg,
    ephemeralKey: ephemeralJwk,
    recipientKey: bobKey,
    ciphertext,
    nonce,
    tag,
    aad: Uint8Array.from(Buffer.from(protectedB64)),
  });

  if (!messageReceived.every((v, i) => message[i] === v)) {
    return 1;
  }
};

export const joseEcdhEsWrapped = () => {
  const bobKey = Key.generate(KeyAlgs.X25519);
  const bobJwk = bobKey.jwkPublic;
  const ephemeralKey = Key.generate(KeyAlgs.X25519);
  const ephemeralJwk = ephemeralKey.jwkPublic;
  const message = Uint8Array.from(Buffer.from('Hello there'));
  const alg = 'ECDH-ES+A128KW';
  const enc = 'A256GCM';
  const apu = 'Alice';
  const apv = 'bob';

  const protectedJson = {
    alg,
    enc,
    apu: base64url(apu),
    apv: base64url(apv),
    epk: ephemeralJwk,
  };
  const protectedString = JSON.stringify(protectedJson);
  const protectedB64 = Buffer.from(protectedString).toString('base64');
  const protectedB64Bytes = Uint8Array.from(Buffer.from(protectedB64));

  const cek = Key.generate(KeyAlgs.AesA256Gcm);

  const encryptedMessage = cek.aeadEncrypt({message, aad: protectedB64Bytes});
  const {tag, nonce, ciphertext} = encryptedMessage.parts;
  const encryptedKey = new EcdhEs({
    algId: Uint8Array.from(Buffer.from(alg)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).senderWrapKey({
    wrapAlg: KeyAlgs.AesA128Kw,
    ephemeralKey,
    recipientKey: bobJwk.toKey(),
    cek,
  }).ciphertext;

  const cekReceiver = new EcdhEs({
    algId: Uint8Array.from(Buffer.from(alg)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).receiverUnwrapKey({
    wrapAlg: KeyAlgs.AesA128Kw,
    encAlg: KeyAlgs.AesA256Gcm,
    ephemeralKey: ephemeralJwk.toKey(),
    recipientKey: bobKey,
    ciphertext: encryptedKey,
  });

  const messageReceived = cekReceiver.aeadDecrypt({
    ciphertext,
    tag,
    nonce,
    aad: protectedB64Bytes,
  });

  if (!messageReceived.every((v, i) => message[i] === v)) {
    return 1;
  }
};

export const joseEcdh1puDirect = () => {
  const aliceKey = Key.generate(KeyAlgs.EcSecp256r1);
  const aliceJwk = aliceKey.jwkPublic;
  const bobKey = Key.generate(KeyAlgs.EcSecp256r1);
  const bobJwk = bobKey.jwkPublic;
  const ephemeralKey = Key.generate(KeyAlgs.EcSecp256r1);
  const ephemeralJwk = ephemeralKey.jwkPublic;
  const message = Uint8Array.from(Buffer.from('Hello there'));
  const alg = 'ECDH-1PU';
  const enc = 'A256GCM';
  const apu = 'Alice';
  const apv = 'Bob';
  const protectedJson = {
    alg,
    enc,
    apu: base64url(apu),
    apv: base64url(apv),
    epk: ephemeralJwk,
  };
  const protectedString = JSON.stringify(protectedJson);
  const protectedB64 = Buffer.from(protectedString).toString('base64');
  const protectedB64Bytes = Uint8Array.from(Buffer.from(protectedB64));

  const encrypedMessage = new Ecdh1PU({
    algId: Uint8Array.from(Buffer.from(enc)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).encryptDirect({
    encAlg: KeyAlgs.AesA256Gcm,
    ephemeralKey,
    message,
    senderKey: aliceKey,
    recipientKey: bobJwk.toKey(),
    aad: protectedB64Bytes,
  });

  const {nonce, tag, ciphertext} = encrypedMessage.parts;

  const messageReceived = new Ecdh1PU({
    algId: Uint8Array.from(Buffer.from(enc)),
    apu: Uint8Array.from(Buffer.from(apu)),
    apv: Uint8Array.from(Buffer.from(apv)),
  }).decryptDirect({
    encAlg: KeyAlgs.AesA256Gcm,
    ephemeralKey,
    senderKey: aliceJwk.toKey(),
    recipientKey: bobKey,
    ciphertext,
    nonce,
    tag,
    aad: protectedB64Bytes,
  });

  if (!messageReceived.every((v, i) => message[i] === v)) {
    return 1;
  }
};
