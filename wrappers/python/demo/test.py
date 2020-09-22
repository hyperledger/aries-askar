import asyncio
import sys

from aries_askar.bindings import generate_raw_key, version
from aries_askar import Store, UpdateEntry

# REPO_URI = "postgres://postgres:pgpass@localhost:5432/test_wallet2"
REPO_URI = "sqlite://test.db"
ENCRYPT = True


def log(*args):
    print(*args, "\n")


async def basic_test():
    if ENCRYPT:
        key = generate_raw_key()
        key_method = "raw"
        print("Generated key:", key)
    else:
        key = None
        key_method = "none"

    async with Store.provision(REPO_URI, key_method, key) as store:
        log(f"Provisioned store: {store}")

        # Insert a new entry
        entry = UpdateEntry(
            "category", "name", b"value", {"~plaintag": "a", "enctag": "b"}
        )
        await store.update([entry])
        print("inserted entry")

        # Count rows by category and (optional) tag filter
        print(
            "count:",
            await store.count("category", {"~plaintag": "a", "enctag": "b"}),
        )

        # Fetch an entry by category and name
        print("fetched entry", await store.fetch("category", "name"))

        # Scan entries by category and (optional) tag filter)
        async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
            print("scan result", row)

        # Create a new record lock and perform an associated update
        lock_entry = UpdateEntry(
            "category", "name", b"value", {"~plaintag": "a", "enctag": "b"}
        )
        async with store.create_lock(lock_entry) as lock:
            print(lock.entry)

            entry2 = UpdateEntry("category2", "name2", b"value2")
            await lock.update([entry2])


async def open_test(key):
    async with Store.open(REPO_URI, key) as store:
        log(f"Opened store: {store}")

        # Scan entries by category and (optional) tag filter)
        async for row in store.scan("category"):
            print("scan result", row)


if __name__ == "__main__":
    log("aries-askar version:", version())

    key = sys.argv[1] if len(sys.argv) > 1 else None

    if key:
        asyncio.get_event_loop().run_until_complete(open_test(key))
    else:
        asyncio.get_event_loop().run_until_complete(basic_test())

    print("done")
