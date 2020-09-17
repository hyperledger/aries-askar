import asyncio

from aries_store.bindings import generate_raw_key, version
from aries_store import Store, UpdateEntry

PASS_KEY = "test-password"


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

        print("row count:", await store.count("category", {"enctag": "b"}))

        entry = await store.fetch("category", "name")
        print(entry)

        async for row in store.scan("category"):
            print("scan result", row)


if __name__ == "__main__":
    log("aries-store-kv version:", version())

    asyncio.get_event_loop().run_until_complete(basic_test())

    print("done")
