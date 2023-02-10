import Foundation
import AskarFramework

public struct KeyEntry {
    let list: KeyEntryList
    let pos: Int32

    public init(list: KeyEntryList, pos: Int32) {
        self.list = list
        self.pos = pos
    }

    public var algorithm: String {
        get throws {
            var out: UnsafePointer<CChar>?
            let error = askar_key_entry_list_get_algorithm(list.handle, pos, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }
            guard let out = out else {
                throw AskarError.wrapperError(message: "Failed to get key entry algorithm")
            }

            let algorithm = String(cString: out)
            askar_string_free(out)
            return algorithm
        }
    }

    public var name: String {
        get throws {
            var out: UnsafePointer<CChar>?
            let error = askar_key_entry_list_get_name(list.handle, pos, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }
            guard let out = out else {
                throw AskarError.wrapperError(message: "Failed to get key entry name")
            }

            let name = String(cString: out)
            askar_string_free(out)
            return name
        }
    }

    public var metadata: String {
        get throws {
            var out: UnsafePointer<CChar>?
            let error = askar_key_entry_list_get_metadata(list.handle, pos, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }
            guard let out = out else {
                throw AskarError.wrapperError(message: "Failed to get key entry metadata")
            }

            let metadata = String(cString: out)
            askar_string_free(out)
            return metadata
        }
    }

    public var tags: [String: String] {
        get throws {
            var out: UnsafePointer<CChar>?
            let error = askar_key_entry_list_get_tags(list.handle, pos, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }
            guard let out = out else {
                throw AskarError.wrapperError(message: "Failed to get key entry tags")
            }

            let tagsJson = String(cString: out)
            askar_string_free(out)
            return try JSONDecoder().decode([String: String].self, from: tagsJson.data(using: .utf8)!)
        }
    }

    public var key: Key {
        get throws {
            var out = LocalKeyHandle()
            let error = askar_key_entry_list_load_local(list.handle, pos, &out)
            if error != Success {
                throw AskarError.nativeError(code: error.rawValue)
            }

            return Key(handle: out)
        }
    }
}

public class KeyEntryList: IteratorProtocol {
    let handle: KeyEntryListHandle
    let length: Int32
    private var pos: Int32 = 0

    public init(handle: KeyEntryListHandle, len: Int? = nil) throws {
        self.handle = handle
        if len != nil {
            self.length = Int32(len!)
            return
        }

        var out: Int32 = 0
        let error = askar_key_entry_list_count(handle, &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }
        self.length = out
    }

    public func next() -> KeyEntry? {
        if pos >= length {
            return nil
        }
        let entry = KeyEntry(list: self, pos: pos)
        pos += 1
        return entry
    }

    public var count: Int {
        return Int(length)
    }

    deinit {
        askar_key_entry_list_free(handle)
    }
}
