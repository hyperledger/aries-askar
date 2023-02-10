import Foundation
import AskarFramework

public class Store {
    public static let URI_SCHEMA = "sqlite://"
    let handle: StoreHandle
    let path: String
    private static var continuation: CheckedContinuation<Any, Error>?
    var openSession: Session?

    private init(handle: StoreHandle, path: String) {
        self.handle = handle
        self.path = path
    }

    public static func provision(path: String, keyMethod: String? = nil, passKey: String? = nil, recreate: Bool = false) async throws -> Store {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Store.continuation = continuation
            let err = askar_store_provision(URI_SCHEMA + path, keyMethod, passKey, nil, recreate ? 1:0, { (_, err, handle) in
                if err != Success {
                    Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Store.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! StoreHandle

        return Store(handle: handle, path: path)
    }

    public static func generateRawKey() throws -> String {
        var out: UnsafePointer<CChar>?
        let error = askar_store_generate_raw_key(ByteBuffer(), &out)
        if error != Success {
            throw AskarError.nativeError(code: error.rawValue)
        }

        let key = String(cString: out!)
        return key
    }

    public static func open(path: String, keyMethod: String? = nil, passKey: String? = nil) async throws -> Store {
        let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Store.continuation = continuation
            let err = askar_store_open(URI_SCHEMA + path, keyMethod, passKey, nil, { (_, err, handle) in
                if err != Success {
                    Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Store.continuation?.resume(returning: handle)
                }
            }, 0)
            if err != Success {
                Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! StoreHandle

        return Store(handle: handle, path: path)
    }

    public func close() async throws {
        if openSession != nil {
            try await openSession!.close()
            openSession = nil
        }

        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Store.continuation = continuation
            let err = askar_store_close(handle, { (_, err) in
                if err != Success {
                    Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Store.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public static func remove(path: String) async throws {
        _ = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Store.continuation = continuation
            let err = askar_store_remove(URI_SCHEMA + path, { (_, err, removed) in
                if err != Success {
                    Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else if removed == 0 {
                    Store.continuation?.resume(throwing: AskarError.wrapperError(message: "Failed to remove store"))
                } else {
                    Store.continuation?.resume(returning: ())
                }
            }, 0)
            if err != Success {
                Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        }
    }

    public func doOpenSession() async throws {
        if openSession != nil {
            throw AskarError.wrapperError(message: "Session already open")
        }

        let session = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Store.continuation = continuation
            let err = askar_session_start(handle, nil, 0 /* do not support transaction */, { (_, err, session) in
                if err != Success {
                    Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Store.continuation?.resume(returning: session)
                }
            }, 0)
            if err != Success {
                Store.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! SessionHandle

        openSession = Session(handle: session)
    }
}
