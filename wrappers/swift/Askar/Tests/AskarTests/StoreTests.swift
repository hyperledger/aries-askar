import XCTest
@testable import Askar

final class StoreTests: XCTestCase {
    var store: AskarStore!
    var session: AskarSession!
    let storeManager = AskarStoreManager()
    let keyFactory = LocalKeyFactory()
    let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    let TEST_ENTRY = [
        "category": "test category",
        "name": "test name",
        "value": "test_value",
        "tags": "{\"~plaintag\": \"a\", \"enctag\": \"b\"}" // We cannot support json tag
    ]
    let URI_SCHEMA = "sqlite://"

    override func setUp() async throws {
        try await super.setUp()

        let storeURL = temporaryDirectoryURL.appendingPathComponent("test.db")
        let key = try storeManager.generateRawStoreKey(seed: nil)
        store = try await storeManager.provision(specUri: URI_SCHEMA + storeURL.path, keyMethod: "raw", passKey: key, profile: nil, recreate: true)
    }

    override func tearDown() async throws {
        if session != nil {
            try await session.close()
        }
        if store != nil {
            let storeURL = temporaryDirectoryURL.appendingPathComponent("test.db")
            try await store.close()
            _ = try await storeManager.remove(specUri: URI_SCHEMA + storeURL.path)
        }
        try await super.tearDown()
    }

    func testStoreClose() async throws {
        session = try await store.session(profile: nil)
        let count = try await session.count(category: "test", tagFilter: nil)
        XCTAssertEqual(count, 0)
    }

    func testInsertUpdate() async throws {
        session = try await store.session(profile: nil)
        try await session.update(
            operation: .insert,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: Array(TEST_ENTRY["value"]!.utf8),
            tags: TEST_ENTRY["tags"]!,
            expiryMs: nil)

        let count = try await session.count(category: TEST_ENTRY["category"]!,
                                            tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}")
        XCTAssertEqual(count, 1)

        if let found = try await session.fetch(category: TEST_ENTRY["category"]!,
                                               name: TEST_ENTRY["name"]!, forUpdate: false) {
            XCTAssertEqual(found.category(), TEST_ENTRY["category"])
            XCTAssertEqual(found.name(), TEST_ENTRY["name"])
            XCTAssertEqual(String(bytes: found.value(), encoding: .utf8), TEST_ENTRY["value"])
            let tags = found.tags()
            XCTAssertEqual(tags["plaintag"], "a")
            XCTAssertEqual(tags["enctag"], "b")
        } else {
            XCTFail("Entry not found")
        }

        let all = try await session.fetchAll(category: TEST_ENTRY["category"]!,
                                             tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}",
                                             limit: nil,
                                             forUpdate: false)
        XCTAssertEqual(all.count, 1)
        let first = all[0]
        XCTAssertEqual(first.name(), TEST_ENTRY["name"])
        XCTAssertEqual(String(bytes: first.value(), encoding: .utf8), TEST_ENTRY["value"]!)


        var newEntry = TEST_ENTRY
        newEntry["value"] = "new value"
        newEntry["tags"] = "{\"upd\": \"tagval\"}"
        try await session.update(
            operation: .replace,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: Array(newEntry["value"]!.utf8),
            tags: newEntry["tags"]!,
            expiryMs: nil)

        if let found = try await session.fetch(category: TEST_ENTRY["category"]!,
                                               name: TEST_ENTRY["name"]!,
                                               forUpdate: false) {
            XCTAssertEqual(String(bytes: found.value(), encoding: .utf8), newEntry["value"])
            XCTAssertEqual(found.tags()["upd"], "tagval")
        } else {
            XCTFail("Entry not found")
        }

        try await session.update(
            operation: .remove,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: [],
            tags: nil,
            expiryMs: nil)

        let empty = try await session.fetch(category: TEST_ENTRY["category"]!,
                                            name: TEST_ENTRY["name"]!,
                                            forUpdate: false)
        XCTAssertNil(empty)
    }

    func testScan() async throws {
        session = try await store.session(profile: nil)
        try await session.update(
            operation: .insert,
            category: TEST_ENTRY["category"]!,
            name: TEST_ENTRY["name"]!,
            value: Array(TEST_ENTRY["value"]!.utf8),
            tags: TEST_ENTRY["tags"]!,
            expiryMs: nil)

        let scan = try await store.scan(profile: nil, categogy: TEST_ENTRY["category"]!, tagFilter: "{\"~plaintag\": \"a\", \"enctag\": \"b\"}", offset: nil, limit: nil)
        let rows = try await scan.fetchAll()
        XCTAssertEqual(rows.count, 1)
        let first = rows[0]
        XCTAssertEqual(first.name(), TEST_ENTRY["name"])
        XCTAssertEqual(String(bytes: first.value(), encoding: .utf8), TEST_ENTRY["value"]!)
    }

    func testKeyStore() async throws {
        session = try await store.session(profile: nil)
        let keypair = try keyFactory.generate(alg: .ed25519, ephemeral: false)
        let keyName = "test_key"
        try await session.insertKey(name: keyName, key: keypair, metadata: "metadata", tags: "{\"a\": \"b\"}", expiryMs: nil)

        var key = try await session.fetchKey(name: keyName, forUpdate: false)
        XCTAssertEqual(key?.name(), keyName)
        XCTAssertEqual(key?.tags()["a"], "b")

        try await session.updateKey(name: keyName, metadata: "new metadata", tags: "{\"a\": \"c\"}", expiryMs: nil)
        key = try await session.fetchKey(name: keyName, forUpdate: false)
        XCTAssertEqual(key?.name(), keyName)
        XCTAssertEqual(key?.tags()["a"], "c")

        let thumbprint = try keypair.toJwkThumbprint(alg: nil)
        XCTAssertEqual(try key?.loadLocalKey().toJwkThumbprint(alg: nil), thumbprint)

        let keylist = try await session.fetchAllKeys(algorithm: "ed25519", thumbprint: thumbprint, tagFilter: "{\"a\": \"c\"}", limit: -1, forUpdate: false)
        XCTAssertEqual(keylist.count, 1)
        XCTAssertEqual(keylist[0].name(), keyName)

        try await session.removeKey(name: keyName)
        key = try await session.fetchKey(name: keyName, forUpdate: false)
        XCTAssertNil(key)
    }
}
