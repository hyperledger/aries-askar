import asyncio
import logging
import os
import sys
import time

from aries_askar.bindings import (
    generate_raw_key,
    version,
)
from aries_askar import Store

logging.basicConfig(level=os.getenv("LOG_LEVEL", "").upper() or None)

if len(sys.argv) > 1:
    REPO_URI = sys.argv[1]
    if REPO_URI == "postgres":
        REPO_URI = "postgres://postgres:pgpass@localhost:5432/askar-test"
else:
    REPO_URI = "sqlite://:memory:"

PERF_ROWS = 10000


def log(*args):
    print(*args, "\n")


async def perf_test():
    key = await generate_raw_key()

    store = await Store.provision(REPO_URI, "raw", key, recreate=True)

    insert_start = time.perf_counter()
    async with store.transaction() as txn:
        # ^ faster within a transaction
        for idx in range(PERF_ROWS):
            await txn.insert(
                "category", f"name-{idx}", b"value", {"~plaintag": "a", "enctag": "b"}
            )
        await txn.commit()
    dur = time.perf_counter() - insert_start
    print(f"insert duration ({PERF_ROWS} rows): {dur:0.2f}s")

    fetch_start = time.perf_counter()
    async with store as session:
        tags = 0
        for idx in range(PERF_ROWS):
            entry = await session.fetch("category", f"name-{idx}")
            tags += len(entry.tags)
    dur = time.perf_counter() - fetch_start
    print(f"fetch duration ({PERF_ROWS} rows, {tags} tags): {dur:0.2f}s")

    rc = 0
    tags = 0
    scan_start = time.perf_counter()
    async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
        rc += 1
        tags += len(row.tags)
    dur = time.perf_counter() - scan_start
    print(f"scan duration ({rc} rows, {tags} tags): {dur:0.2f}s")

    await store.close()


if __name__ == "__main__":
    log("aries-askar version:", version())

    asyncio.get_event_loop().run_until_complete(perf_test())

    print("done")
