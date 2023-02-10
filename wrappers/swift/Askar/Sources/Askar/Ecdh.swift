import Foundation
import AskarFramework

public class EcdhEs {
    let algId: FfiByteBuffer
    let apu: FfiByteBuffer
    let apv: FfiByteBuffer

    public init(algId: String, apu: String? = nil, apv: String? = nil) {
        self.algId = FfiByteBuffer(fromString: algId)
        self.apu = FfiByteBuffer(fromString: apu)
        self.apv = FfiByteBuffer(fromString: apv)
    }

    func deriveKey(encAlg: KeyAlg, ephemeralKey: Key, receiverKey: Key, receive: Bool) throws -> Key {
        var handle = LocalKeyHandle()
        let error = askar_key_derive_ecdh_es(encAlg.rawValue, ephemeralKey.handle, receiverKey.handle, algId.buffer, apu.buffer, apv.buffer, receive ? 1:0, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public func encryptDirect(encAlg: KeyAlg,
                              ephemeralKey: Key,
                              receiverKey: Key,
                              message: Data,
                              aad: Data? = nil,
                              nonce: Data? = nil) throws -> Encrypted {
        let derived = try deriveKey(encAlg: encAlg, ephemeralKey: ephemeralKey, receiverKey: receiverKey, receive: false)
        return try derived.aeadEncrypt(message: message, nonce: nonce, aad: aad)
    }

    public func decryptDirect(encAlg: KeyAlg,
                              ephemeralKey: Key,
                              receiverKey: Key,
                              ciphertext: Data,
                              nonce: Data,
                              tag: Data,
                              aad: Data? = nil) throws -> Data {
        let derived = try deriveKey(encAlg: encAlg, ephemeralKey: ephemeralKey, receiverKey: receiverKey, receive: true)
        return try derived.aeadDecrypt(ciphertext: ciphertext, nonce: nonce, tag: tag, aad: aad)
    }

    public func senderWrapKey(wrapAlg: KeyAlg,
                              ephemeralKey: Key,
                              receiverKey: Key,
                              cek: Key) throws -> Encrypted {
        let derived = try deriveKey(encAlg: wrapAlg, ephemeralKey: ephemeralKey, receiverKey: receiverKey, receive: false)
        return try derived.wrapKey(other: cek)
    }

    public func receiverUnwrapKey(wrapAlg: KeyAlg,
                                  encAlg: KeyAlg,
                                  ephemeralKey: Key,
                                  receiverKey: Key,
                                  ciphertext: Data,
                                  nonce: Data? = nil,
                                  tag: Data? = nil) throws -> Key {
        let derived = try deriveKey(encAlg: wrapAlg, ephemeralKey: ephemeralKey, receiverKey: receiverKey, receive: true)
        return try derived.unwrapKey(alg: encAlg, ciphertext: ciphertext, nonce: nonce, tag: tag)
    }
}

public class Ecdh1PU {
    let algId: FfiByteBuffer
    let apu: FfiByteBuffer
    let apv: FfiByteBuffer

    public init(algId: String, apu: String? = nil, apv: String? = nil) {
        self.algId = FfiByteBuffer(fromString: algId)
        self.apu = FfiByteBuffer(fromString: apu)
        self.apv = FfiByteBuffer(fromString: apv)
    }

    func deriveKey(encAlg: KeyAlg, ephemeralKey: Key, senderKey: Key, receiverKey: Key, ccTag: Data? = nil, receive: Bool) throws -> Key {
        var handle = LocalKeyHandle()
        let ccTagBuf = FfiByteBuffer(fromData: ccTag)
        let error = askar_key_derive_ecdh_1pu(encAlg.rawValue, ephemeralKey.handle, senderKey.handle, receiverKey.handle, algId.buffer, apu.buffer, apv.buffer, ccTagBuf.buffer, receive ? 1:0, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public func encryptDirect(encAlg: KeyAlg,
                              ephemeralKey: Key,
                              senderKey: Key,
                              receiverKey: Key,
                              message: Data,
                              aad: Data? = nil,
                              nonce: Data? = nil) throws -> Encrypted {
        let derived = try deriveKey(encAlg: encAlg, ephemeralKey: ephemeralKey, senderKey: senderKey, receiverKey: receiverKey, receive: false)
        return try derived.aeadEncrypt(message: message, nonce: nonce, aad: aad)
    }

    public func decryptDirect(encAlg: KeyAlg,
                              ephemeralKey: Key,
                              senderKey: Key,
                              receiverKey: Key,
                              ciphertext: Data,
                              nonce: Data,
                              tag: Data,
                              aad: Data? = nil) throws -> Data {
        let derived = try deriveKey(encAlg: encAlg, ephemeralKey: ephemeralKey, senderKey: senderKey, receiverKey: receiverKey, receive: true)
        return try derived.aeadDecrypt(ciphertext: ciphertext, nonce: nonce, tag: tag, aad: aad)
    }

    public func senderWrapKey(wrapAlg: KeyAlg,
                              ephemeralKey: Key,
                              senderKey: Key,
                              receiverKey: Key,
                              cek: Key,
                              ccTag: Data) throws -> Encrypted {
        let derived = try deriveKey(encAlg: wrapAlg, ephemeralKey: ephemeralKey, senderKey: senderKey, receiverKey: receiverKey, ccTag: ccTag, receive: false)
        return try derived.wrapKey(other: cek)
    }

    public func receiverUnwrapKey(wrapAlg: KeyAlg,
                                  encAlg: KeyAlg,
                                  ephemeralKey: Key,
                                  senderKey: Key,
                                  receiverKey: Key,
                                  ciphertext: Data,
                                  ccTag: Data,
                                  nonce: Data? = nil,
                                  tag: Data? = nil) throws -> Key {
        let derived = try deriveKey(encAlg: encAlg, ephemeralKey: ephemeralKey, senderKey: senderKey, receiverKey: receiverKey, ccTag: ccTag, receive: true)
        return try derived.unwrapKey(alg: wrapAlg, ciphertext: ciphertext, nonce: nonce, tag: tag)
    }
}
