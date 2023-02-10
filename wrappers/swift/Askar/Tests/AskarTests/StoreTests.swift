import XCTest
@testable import Askar

final class StoreTests: XCTestCase {
    var store: Store!
    var session: Session!
    let TEST_ENTRY = [
        "category": "test category",
        "name": "test name",
        "value": "test_value",
        "tags": "{\"~plaintag\": \"a\", \"enctag\": \"b\"}" // We cannot support json tag
    ]

    override func setUp() async throws {
        try await super.setUp()

        let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        let storeURL = temporaryDirectoryURL.appendingPathComponent("test.db")
        let key = try Store.generateRawKey()
        store = try await Store.provision(path: storeURL.path, keyMethod: "raw", passKey: key, recreate: true)
        try await store.doOpenSession()
        session = store.openSession!
    }

    override func tearDown() async throws {
        if store != nil {
            try await store.close()
            try await Store.remove(path: store.path)
        }
        try await super.tearDown()
    }

    func testInsertUpdate() async throws {
        try await session.update(
            operation: EntryOperation.INSERT,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: TEST_ENTRY["value"]!.data(using: .utf8),
            tags: TEST_ENTRY["tags"]!)

        let count = try await session.count(category: TEST_ENTRY["category"]!,
                                            tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}")
        XCTAssertEqual(count, 1)

        if let found = try await session.fetch(category: TEST_ENTRY["category"]!,
                                               name: TEST_ENTRY["name"]!) {
            XCTAssertEqual(try found.category, TEST_ENTRY["category"])
            XCTAssertEqual(try found.name, TEST_ENTRY["name"])
            XCTAssertEqual(String(data: try found.value, encoding: .utf8), TEST_ENTRY["value"])
            XCTAssertEqual(try found.tags["~plaintag"], "a")
            XCTAssertEqual(try found.tags["enctag"], "b")
        } else {
            XCTFail("Entry not found")
        }

        let all = try await session.fetchAll(category: TEST_ENTRY["category"]!,
                                             tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}")
        XCTAssertEqual(all?.count, 1)
        if let first = all?.next() {
            XCTAssertEqual(try first.name, TEST_ENTRY["name"])
            XCTAssertEqual(String(data: try first.value, encoding: .utf8), TEST_ENTRY["value"]!)
        } else {
            XCTFail("Entry not found")
        }

        var newEntry = TEST_ENTRY
        newEntry["value"] = "new value"
        newEntry["tags"] = "{\"upd\": \"tagval\"}"
        try await session.update(
            operation: EntryOperation.REPLACE,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: newEntry["value"]!.data(using: .utf8),
            tags: newEntry["tags"]!)

        if let found = try await session.fetch(category: TEST_ENTRY["category"]!,
                                               name: TEST_ENTRY["name"]!) {
            XCTAssertEqual(String(data: try found.value, encoding: .utf8), newEntry["value"])
            XCTAssertEqual(try found.tags["upd"], "tagval")
        } else {
            XCTFail("Entry not found")
        }

        try await session.update(
            operation: EntryOperation.REMOVE,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!)

        let empty = try await session.fetch(category: TEST_ENTRY["category"]!,
                                            name: TEST_ENTRY["name"]!)
        XCTAssertNil(empty)
    }

    func testScan() async throws {
        try await session.update(
            operation: EntryOperation.INSERT,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: TEST_ENTRY["value"]!.data(using: .utf8),
            tags: TEST_ENTRY["tags"]!)

        let scan = Scan(store: store, category: TEST_ENTRY["category"]!, tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}")
        let rows = try await scan.fetchAll()
        XCTAssertEqual(rows.count, 1)
        let first = rows[0]
        XCTAssertEqual(try first.name, TEST_ENTRY["name"])
        XCTAssertEqual(String(data: try first.value, encoding: .utf8), TEST_ENTRY["value"]!)
    }

    func testKeyStore() async throws {
        let keypair = try Key.generate(alg: KeyAlg.ED25519)
        let keyName = "test_key"
        try await session.insertKey(keypair, name: keyName, meta: "metadata", tags: "{\"a\": \"b\"}")

        var key = try await session.fetchKey(name: keyName)
        XCTAssertEqual(try key?.name, keyName)
        XCTAssertEqual(try key?.tags["a"], "b")

        try await session.updateKey(name: keyName, meta: "new metadata", tags: "{\"a\": \"c\"}")
        key = try await session.fetchKey(name: keyName)
        XCTAssertEqual(try key?.name, keyName)
        XCTAssertEqual(try key?.tags["a"], "c")

        let thumbprint = try keypair.getJwkThumbprint()
        XCTAssertEqual(try key?.key.getJwkThumbprint(), thumbprint)

        let keylist = try await session.fetchAllKeys(alg: KeyAlg.ED25519, thumbprint: thumbprint, tagFilter: "{\"a\": \"c\"}", limit: 1)
        XCTAssertEqual(keylist?.count, 1)
        XCTAssertEqual(try keylist?.next()?.name, keyName)

        try await session.removeKey(name: keyName)
        key = try await session.fetchKey(name: keyName)
        XCTAssertNil(key)
    }
}
