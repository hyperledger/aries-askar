import Foundation
import AskarFramework

public class Session {
    let _handle: SessionHandle
    private static var continuation: CheckedContinuation<Any, Error>?

    public init(handle: SessionHandle) {
        self._handle = handle
    }

    public func count(category: String, tagFilter: String) async throws -> Int {
        let count = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_count(_handle, category, tagFilter, { (_, err, count) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: count)
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! Int64

        return Int(count)
    }

    public func fetch(category: String, name: String, forUpdate: Bool = false) async throws -> Entry? {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_fetch(_handle, category, name, forUpdate ? 1:0, { (_, err, handle) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! EntryListHandle

        if !handle.isEmpty {
            return try EntryList(handle: handle, len: 1).next()
        } else {
            return nil
        }
    }

    public func fetchAll(category: String, tagFilter: String? = nil, limit: Int = -1, forUpdate: Bool = false) async throws -> EntryList? {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_fetch_all(_handle, category, tagFilter, Int64(limit), forUpdate ? 1:0, { (_, err, handle) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! EntryListHandle

        if !handle.isEmpty {
            return try EntryList(handle: handle)
        } else {
            return nil
        }
    }

    public func update(operation: EntryOperation, category: String, name: String, value: Data? = nil, tags: String? = nil, expiryMillis: Int = -1) async throws {
        let byteBuf = FfiByteBuffer(fromData: value)
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_update(_handle, operation.rawValue, category, name, byteBuf.buffer, tags, Int64(expiryMillis), { (_, err) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public func insertKey(_ key: Key, name: String, meta: String? = nil, tags: String? = nil, expiryMillis: Int = -1) async throws {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_insert_key(_handle, key.handle, name, meta, tags, Int64(expiryMillis), { (_, err) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public func fetchKey(name: String, forUpdate: Bool = false) async throws -> KeyEntry? {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_fetch_key(_handle, name, forUpdate ? 1:0, { (_, err, handle) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! KeyEntryListHandle

        if !handle.isEmpty {
            return try KeyEntryList(handle: handle, len: 1).next()
        } else {
            return nil
        }
    }

    public func fetchAllKeys(alg: KeyAlg? = nil, thumbprint: String? = nil, tagFilter: String? = nil, limit: Int = -1, forUpdate: Bool = false) async throws -> KeyEntryList? {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_fetch_all_keys(_handle, alg?.rawValue, thumbprint, tagFilter, Int64(limit), forUpdate ? 1:0, { (_, err, handle) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! KeyEntryListHandle

        if !handle.isEmpty {
            return try KeyEntryList(handle: handle)
        } else {
            return nil
        }
    }

    public func updateKey(name: String, meta: String? = nil, tags: String? = nil, expiryMillis: Int = -1) async throws {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_update_key(_handle, name, meta, tags, Int64(expiryMillis), { (_, err) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public func removeKey(name: String) async throws {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_remove_key(_handle, name, { (_, err) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public func close() async throws {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Session.continuation = continuation
            let err = askar_session_close(_handle, 0, { (_, err) in
                if err != Success {
                    Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Session.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Session.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }
}
