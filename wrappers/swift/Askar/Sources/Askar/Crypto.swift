import Foundation
import AskarFramework

public class Crypto {
    public static func randomNonce() throws -> Data {
        var buf = SecretBuffer()
        let error = askar_key_crypto_box_random_nonce(&buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public static func box(receiverKey: Key, senderKey: Key, message: Data, nonce: Data) throws -> Data {
        var buf = SecretBuffer()
        let messageBuf = FfiByteBuffer(fromData: message)
        let nonceBuf = FfiByteBuffer(fromData: nonce)
        let error = askar_key_crypto_box(receiverKey.handle, senderKey.handle, messageBuf.buffer, nonceBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public static func boxOpen(receiverKey: Key, senderKey: Key, message: Data, nonce: Data) throws -> Data {
        var buf = SecretBuffer()
        let messageBuf = FfiByteBuffer(fromData: message)
        let nonceBuf = FfiByteBuffer(fromData: nonce)
        let error = askar_key_crypto_box_open(receiverKey.handle, senderKey.handle, messageBuf.buffer, nonceBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public static func boxSeal(receiverKey: Key, message: Data) throws -> Data {
        var buf = SecretBuffer()
        let messageBuf = FfiByteBuffer(fromData: message)
        let error = askar_key_crypto_box_seal(receiverKey.handle, messageBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }

    public static func boxSealOpen(receiverKey: Key, message: Data) throws -> Data {
        var buf = SecretBuffer()
        let messageBuf = FfiByteBuffer(fromData: message)
        let error = askar_key_crypto_box_seal_open(receiverKey.handle, messageBuf.buffer, &buf)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        return buf.toData()
    }
}
