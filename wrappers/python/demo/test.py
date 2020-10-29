import asyncio
import sys

from aries_askar.bindings import derive_verkey, generate_raw_key, version
from aries_askar import KeyAlg, Store, UpdateEntry

# REPO_URI = "postgres://postgres:pgpass@localhost:5432/test_wallet2"
REPO_URI = "sqlite://:memory:"
ENCRYPT = True


def log(*args):
    print(*args, "\n")


async def basic_test():
    if ENCRYPT:
        key = generate_raw_key(b"00000000000000000000000000000My1")
        key_method = "raw"
        log("Generated raw key:", key)
    else:
        key = None
        key_method = "none"

    # Derive a verkey
    verkey = derive_verkey(KeyAlg.ED25519, b"testseedtestseedtestseedtestseed")
    log("Derive verkey:", verkey)

    # Provision the store
    async with Store.provision(REPO_URI, key_method, key) as store:
        log("Provisioned store:", store)

        # Insert a new entry
        entry = UpdateEntry(
            "category", "name", b"value", {"~plaintag": "a", "enctag": "b"}
        )
        await store.update([entry])
        log("Inserted entry")

        # Count rows by category and (optional) tag filter
        log(
            "Row count:",
            await store.count("category", {"~plaintag": "a", "enctag": "b"}),
        )

        # Fetch an entry by category and name
        log("Fetched entry:", await store.fetch("category", "name"))

        # Scan entries by category and (optional) tag filter)
        async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
            log("Scan result:", row)

        # Create a new record lock and perform an associated update
        async with store.create_lock("category", "name", b"init-value") as lock:
            log("Lock entry:", lock.entry, "\nNew record:", lock.new_record)

            entry2 = UpdateEntry("category2", "name2", b"value2")
            await lock.update([entry2])

        # Create a new keypair
        key_ident = await store.create_keypair(KeyAlg.ED25519)
        log("Created key:", key_ident)

        # Fetch keypair
        key = await store.fetch_keypair(key_ident)
        log("Fetch key:", key, "\nKey params:", key.params)

        # Sign a message
        signature = await store.sign_message(key_ident, b"my message")
        log("Signature:", signature)

        # Verify signature
        verify = await store.verify_signature(key_ident, b"my message", signature)
        log("Verify signature:", verify)

        # Pack message
        packed = await store.pack_message([key_ident], key_ident, b"my message")
        log("Packed message:", packed)

        # Unpack message
        unpacked = await store.unpack_message(packed)
        log("Unpacked message:", unpacked)


async def open_test(key):
    async with Store.open(REPO_URI, key) as store:
        log("Opened store:", store)

        # Scan entries by category and (optional) tag filter)
        async for row in store.scan("category"):
            log("Scan result:", row)


if __name__ == "__main__":
    log("aries-askar version:", version())

    key = sys.argv[1] if len(sys.argv) > 1 else None

    if key:
        asyncio.get_event_loop().run_until_complete(open_test(key))
    else:
        asyncio.get_event_loop().run_until_complete(basic_test())

    log("done")
