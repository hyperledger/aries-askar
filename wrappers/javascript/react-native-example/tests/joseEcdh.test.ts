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
