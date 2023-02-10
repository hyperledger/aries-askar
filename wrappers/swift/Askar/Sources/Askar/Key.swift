import Foundation
import AskarFramework

public class Key {
    let handle: LocalKeyHandle

    public init(handle: LocalKeyHandle) {
        self.handle = handle
    }

    deinit {
        askar_key_free(handle)
    }

    public static func generate(alg: KeyAlg, ephemeral: Bool = false) throws -> Key {
        var handle = LocalKeyHandle()
        let error = askar_key_generate(alg.rawValue, ephemeral ? 1:0, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public static func fromSeed(_ seed: String, alg: KeyAlg, method: SeedMethod? = nil) throws -> Key {
        var handle = LocalKeyHandle()
        let ffi = FfiByteBuffer(fromString: seed)
        let error = askar_key_from_seed(alg.rawValue, ffi.buffer, method?.rawValue, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public static func fromSecretBytes(_ secret: Data, alg: KeyAlg) throws -> Key {
        var handle = LocalKeyHandle()
        let ffi = FfiByteBuffer(fromData: secret)
        let error = askar_key_from_secret_bytes(alg.rawValue, ffi.buffer, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public static func fromPublicBytes(_ data: Data, alg: KeyAlg) throws -> Key {
        var handle = LocalKeyHandle()
        let ffi = FfiByteBuffer(fromData: data)
        let error = askar_key_from_public_bytes(alg.rawValue, ffi.buffer, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public static func fromJwk(_ jwk: Data) throws -> Key {
        var handle = LocalKeyHandle()
        let ffi = FfiByteBuffer(fromData: jwk)
        let error = askar_key_from_jwk(ffi.buffer, &handle)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: handle)
    }

    public var algorithm: KeyAlg {
        get throws {
            var out: UnsafePointer<CChar>?
            let error = askar_key_get_algorithm(handle, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }

            guard let out = out, let alg = KeyAlg(rawValue: String(cString: out)) else {
                throw AskarError.wrapperError(message: "Could not get algorithm")
            }

            return alg
        }
    }

    public func convertKey(alg: KeyAlg) throws -> Key {
        var out = LocalKeyHandle()
        let error = askar_key_convert(handle, alg.rawValue, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: out)
    }

    public func keyExchange(alg: KeyAlg, pk: Key) throws -> Key {
        var out = LocalKeyHandle()
        let error = askar_key_from_key_exchange(alg.rawValue, handle, pk.handle, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: out)
    }

    public func getPublicBytes() throws -> Data {
        var buf = SecretBuffer()
        let error = askar_key_get_public_bytes(handle, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func getSecretBytes() throws -> Data {
        var buf = SecretBuffer()
        let error = askar_key_get_secret_bytes(handle, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func getJwkPublic(alg: KeyAlg? = nil) throws -> String {
        var out: UnsafePointer<CChar>?
        let error = askar_key_get_jwk_public(handle, alg?.rawValue, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return String(cString: out!)
    }

    public func getJwkSecret() throws -> Data {
        var buf = SecretBuffer()
        let error = askar_key_get_jwk_secret(handle, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func getJwkThumbprint(alg: KeyAlg? = nil) throws -> String {
        var out: UnsafePointer<CChar>?
        let error = askar_key_get_jwk_thumbprint(handle, alg?.rawValue, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return String(cString: out!)
    }

    public func aeadParams() throws -> AeadParams {
        var out = AeadParams()
        let error = askar_key_aead_get_params(handle, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return out
    }

    public func aeadRandomNonce() throws -> Data {
        var buf = SecretBuffer()
        let error = askar_key_aead_random_nonce(handle, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func aeadEncrypt(message: Data, nonce: Data? = nil, aad: Data? = nil) throws -> Encrypted {
        var buf = EncryptedBuffer()
        let messageBuf = FfiByteBuffer(fromData: message)
        let nonceBuf = FfiByteBuffer(fromData: nonce)
        let aadBuf = FfiByteBuffer(fromData: aad)
        let error = askar_key_aead_encrypt(handle, messageBuf.buffer, nonceBuf.buffer, aadBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Encrypted(buf: buf)
    }

    public func aeadDecrypt(ciphertext: Data, nonce: Data, tag: Data? = nil, aad: Data? = nil) throws -> Data {
        var buf = SecretBuffer()
        let ciphertextBuf = FfiByteBuffer(fromData: ciphertext)
        let nonceBuf = FfiByteBuffer(fromData: nonce)
        let tagBuf = FfiByteBuffer(fromData: tag)
        let aadBuf = FfiByteBuffer(fromData: aad)
        let error = askar_key_aead_decrypt(handle, ciphertextBuf.buffer, nonceBuf.buffer, tagBuf.buffer, aadBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func aeadDecrypt(encrypted: Encrypted, nonce: Data, tag: Data? = nil, aad: Data? = nil) throws -> Data {
        // In line with the Python wrapper: use ciphertextAndTag for ciphertext and override the given nonce.
        return try aeadDecrypt(ciphertext: encrypted.ciphertextAndTag, nonce: encrypted.nonce, tag: tag, aad: aad)
    }

    public func signMessage(_ message: Data) throws -> Data {
        var buf = SecretBuffer()
        let ffi = FfiByteBuffer(fromData: message)
        let error = askar_key_sign_message(handle, ffi.buffer, nil, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public func verifySignature(message: Data, signature: Data) throws -> Bool {
        var out: Int8 = 0
        let messageBuf = FfiByteBuffer(fromData: message)
        let signatureBuf = FfiByteBuffer(fromData: signature)
        let error = askar_key_verify_signature(handle, messageBuf.buffer, signatureBuf.buffer, nil, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return out != 0
    }

    public func wrapKey(other: Key, nonce: Data? = nil) throws -> Encrypted {
        var buf = EncryptedBuffer()
        let ffi = FfiByteBuffer(fromData: nonce)
        let error = askar_key_wrap_key(handle, other.handle, ffi.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Encrypted(buf: buf)
    }

    public func unwrapKey(alg: KeyAlg, ciphertext: Data, nonce: Data? = nil, tag: Data? = nil) throws -> Key {
        var out = LocalKeyHandle()
        let ciphertextBuf = FfiByteBuffer(fromData: ciphertext)
        let nonceBuf = FfiByteBuffer(fromData: nonce)
        let tagBuf = FfiByteBuffer(fromData: tag)
        let error = askar_key_unwrap_key(handle, alg.rawValue, ciphertextBuf.buffer, nonceBuf.buffer, tagBuf.buffer, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return Key(handle: out)
    }

    public func unwrapKey(alg: KeyAlg, encrypted: Encrypted, nonce: Data? = nil, tag: Data? = nil) throws -> Key {
        // In line with the Python wrapper: use ciphertextAndTag for ciphertext and do not override the given nonce.
        return try unwrapKey(alg: alg, ciphertext: encrypted.ciphertextAndTag, nonce: nonce, tag: tag)
    }
}
