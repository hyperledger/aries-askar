import asyncio

from aries_askar.bindings import generate_raw_key, version
from aries_askar import Store, UpdateEntry


def log(*args):
    print(*args, "\n")


async def basic_test():
    key = generate_raw_key()
    print("Generated key:", key)

    async with Store.provision("sqlite://test.db", "raw", key) as store:
        log(f"Provisioned store: {store}")

        entry = UpdateEntry(
            "category", "name", b"value", {"~plaintag": "a", "enctag": "b"}
        )
        await store.update([entry])

        print("row count:", await store.count("category"))

        entry = await store.fetch("category", "name")
        print(entry)

        async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
            print("scan result", row)

        lock_entry = UpdateEntry(
            "category", "name", b"value", {"~plaintag": "a", "enctag": "b"}
        )

        async with store.create_lock(lock_entry) as lock:
            print(lock.entry)

            entry2 = UpdateEntry("category2", "name2", b"value2")
            await lock.update([entry2])


if __name__ == "__main__":
    log("aries-askar version:", version())

    asyncio.get_event_loop().run_until_complete(basic_test())

    print("done")
