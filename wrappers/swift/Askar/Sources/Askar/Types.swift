import Foundation
import AskarFramework

public class FfiByteBuffer {
    let buffer: ByteBuffer
    let pointer: UnsafeMutablePointer<UInt8>?

    init(fromData: Data?) {
        if let data = fromData {
            pointer = UnsafeMutablePointer<UInt8>.allocate(capacity: data.count)
            pointer!.initialize(repeating: 0, count: data.count)
            data.copyBytes(to: pointer!, count: data.count)
            buffer = ByteBuffer(len: Int64(data.count), data: pointer)
        } else {
            pointer = nil
            buffer = ByteBuffer(len: 0, data: nil)
        }
    }

    convenience init(fromString: String?) {
        self.init(fromData: fromString?.data(using: .utf8))
    }

    deinit {
        pointer?.deallocate()
    }
}

public extension ByteBuffer {
    func toData() -> Data {
        return Data(bytes: UnsafeMutableRawPointer(data), count: Int(len))
    }
}

public extension SecretBuffer {
    // Deallocate the buffer here
    func toData() -> Data {
        let data = Data(bytes: data, count: Int(len))
        askar_buffer_free(self)
        return data
    }
}

extension EntryListHandle {
    var isEmpty: Bool {
        return self._0 == nil
    }
}

extension KeyEntryListHandle {
    var isEmpty: Bool {
        return self._0 == nil
    }
}

public class Encrypted {
    public let buf: EncryptedBuffer

    public init(buf: EncryptedBuffer) {
        self.buf = buf
    }

    deinit {
        askar_buffer_free(buf.buffer)
    }

    public var ciphertextAndTag: Data {
        return Data(bytes: buf.buffer.data, count: Int(buf.nonce_pos))
    }

    public var ciphertext: Data {
        return Data(bytes: buf.buffer.data, count: Int(buf.tag_pos))
    }

    public var tag: Data {
        return Data(bytes: buf.buffer.data.advanced(by: Int(buf.tag_pos)), count: Int(buf.nonce_pos - buf.tag_pos))
    }

    public var nonce: Data {
        return Data(bytes: buf.buffer.data.advanced(by: Int(buf.nonce_pos)), count: Int(buf.buffer.len - buf.nonce_pos))
    }

    public var parts: (ciphertext: Data, tag: Data, nonce: Data) {
        return (ciphertext, tag, nonce)
    }
}

public enum EntryOperation: Int8 {
    case INSERT = 0
    case REPLACE = 1
    case REMOVE = 2
}

public enum SeedMethod: String {
    case BlsKeyGen = "bls_keygen"
}

public enum KeyAlg: String {
    case A128GCM = "a128gcm"
    case A256GCM = "a256gcm"
    case A128CBC_HS256 = "a128cbchs256"
    case A256CBC_HS512 = "a256cbchs512"
    case A128KW = "a128kw"
    case A256KW = "a256kw"
    case BLS12_381_G1 = "bls12381g1"
    case BLS12_381_G2 = "bls12381g2"
    case BLS12_381_G1G2 = "bls12381g1g2"
    case C20P = "c20p"
    case XC20P = "xc20p"
    case ED25519 = "ed25519"
    case X25519 = "x25519"
    case K256 = "k256"
    case P256 = "p256"
}
