import Foundation
import AskarFramework

public class Scan: AsyncIteratorProtocol {
    let store: Store
    let category: String
    let tagFilter: String
    let offset: Int64
    let limit: Int64
    var handle: ScanHandle?
    var list: EntryList?
    private static var continuation: CheckedContinuation<Any, Error>?

    public init(store: Store, category: String, tagFilter: String, offset: Int64 = 0, limit: Int64 = -1) {
        self.store = store
        self.category = category
        self.tagFilter = tagFilter
        self.offset = offset
        self.limit = limit
    }

    func scanNext() async throws -> EntryList? {
        let list = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
            Scan.continuation = continuation
            let err = askar_scan_next(handle!, { (_, err, list) in
                if err != Success {
                    Scan.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                } else {
                    Scan.continuation?.resume(returning: list)
                }
            }, 0)
            if err != Success {
                Scan.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
            }
        } as! EntryListHandle

        if list.isEmpty {
            return nil
        } else {
            return try EntryList(handle: list)
        }
    }

    public func next() async throws -> Entry? {
        if handle == nil {
            let handle = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Any, Error>) in
                Scan.continuation = continuation
                let err = askar_scan_start(store.handle, nil, category, tagFilter, offset, limit, { (_, err, handle) in
                    if err != Success {
                        Scan.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                    } else {
                        Scan.continuation?.resume(returning: handle)
                    }
                }, 0)
                if err != Success {
                    Scan.continuation?.resume(throwing: AskarError.nativeError(code: err.rawValue))
                }
            } as! ScanHandle
            self.handle = handle
            self.list = try await scanNext()
            if self.list == nil {
                return nil
            }
        }

        let entry = list!.next()
        if entry != nil {
            return entry
        }
        self.list = try await scanNext()
        if self.list == nil {
            return nil
        }
        return self.list!.next()
    }

    public func fetchAll() async throws -> [Entry] {
        var entries: [Entry] = []
        while let entry = try await self.next() {
            entries.append(entry)
        }
        return entries
    }

    deinit {
        if handle != nil {
            askar_scan_free(handle!)
        }
    }
}
