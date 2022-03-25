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
        REPO_URI = "postgres://postgres:mysecretpassword@localhost:5432/askar-test"
else:
    REPO_URI = "sqlite://:memory:"

PERF_ROWS = 10000


def log(*args):
    print(*args, "\n")


async def perf_test():
    key = generate_raw_key()

    store = await Store.provision(REPO_URI, "raw", key, recreate=True)

    insert_start = time.perf_counter()
    async with store.session() as session:
        for idx in range(PERF_ROWS):
            await session.insert(
                "seq",
                f"name-{idx}",
                b"value",
                {"~plaintag": "a", "enctag": "b"},
            )
    dur = time.perf_counter() - insert_start
    print(f"sequential insert duration ({PERF_ROWS} rows): {dur:0.2f}s")

    insert_start = time.perf_counter()
    async with store.transaction() as txn:
        # ^ should be faster within a transaction
        for idx in range(PERF_ROWS):
            await txn.insert(
                "txn",
                f"name-{idx}",
                b"value",
                {"~plaintag": "a", "enctag": "b"},
            )
        await txn.commit()
    dur = time.perf_counter() - insert_start
    print(f"transaction batch insert duration ({PERF_ROWS} rows): {dur:0.2f}s")

    tags = 0
    fetch_start = time.perf_counter()
    async with store as session:
        for idx in range(PERF_ROWS):
            entry = await session.fetch("seq", f"name-{idx}")
            tags += len(entry.tags)
    dur = time.perf_counter() - fetch_start
    print(f"fetch duration ({PERF_ROWS} rows, {tags} tags): {dur:0.2f}s")

    rc = 0
    tags = 0
    scan_start = time.perf_counter()
    async for row in store.scan("seq", {"~plaintag": "a", "enctag": "b"}):
        rc += 1
        tags += len(row.tags)
    dur = time.perf_counter() - scan_start
    print(f"scan duration ({rc} rows, {tags} tags): {dur:0.2f}s")

    async with store as session:
        await session.insert("seq", "count", "0", {"~plaintag": "a", "enctag": "b"})
        update_start = time.perf_counter()
        count = 0
        for idx in range(PERF_ROWS):
            count += 1
            await session.replace(
                "seq", "count", str(count), {"~plaintag": "a", "enctag": "b"}
            )
    dur = time.perf_counter() - update_start
    print(f"unchecked update duration ({PERF_ROWS} rows): {dur:0.2f}s")

    async with store as session:
        await session.insert("txn", "count", "0", {"~plaintag": "a", "enctag": "b"})
    update_start = time.perf_counter()
    for idx in range(PERF_ROWS):
        async with store.transaction() as txn:
            row = await txn.fetch("txn", "count", for_update=True)
            count = str(int(row.value) + 1)
            await txn.replace("txn", "count", count, {"~plaintag": "a", "enctag": "b"})
            await txn.commit()
    dur = time.perf_counter() - update_start
    print(f"transactional update duration ({PERF_ROWS} rows): {dur:0.2f}s")

    await store.close()


if __name__ == "__main__":
    log("aries-askar version:", version())

    asyncio.get_event_loop().run_until_complete(perf_test())

    print("done")
