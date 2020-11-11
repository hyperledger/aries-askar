import asyncio
import sys

from aries_askar.bindings import (
    derive_verkey,
    generate_raw_key,
    verify_signature,
    version,
)
from aries_askar import KeyAlg, Store

if len(sys.argv) > 1:
    REPO_URI = sys.argv[1]
    if REPO_URI == "postgres":
        REPO_URI = "postgres://postgres:pgpass@localhost:5432/askar-test"
else:
    REPO_URI = "sqlite://:memory:"

ENCRYPT = True


def log(*args):
    print(*args, "\n")


async def basic_test():
    if ENCRYPT:
        key = generate_raw_key(b"00000000000000000000000000000My1")
        key_method = "raw"
        log("Generated raw wallet key:", key)
    else:
        key = None
        key_method = "none"

    # Derive a verkey
    verkey = derive_verkey(KeyAlg.ED25519, b"testseedtestseedtestseedtestseed")
    log("Derive verkey:", verkey)

    # Provision the store
    store = await Store.provision(REPO_URI, key_method, key, True)
    log("Provisioned store:", store)

    # start a new transaction
    async with store.transaction() as txn:

        # Insert a new entry
        await txn.insert(
            "category", "name", b"value", {"~plaintag": "a", "enctag": ["b", "c"]}
        )
        log("Inserted entry")

        # Count rows by category and (optional) tag filter
        log(
            "Row count:",
            await txn.count("category", {"~plaintag": "a", "enctag": "b"}),
        )

        # Fetch an entry by category and name
        log("Fetch entry:", await txn.fetch("category", "name"))

        # Fetch entries by category and tag filter
        log(
            "Fetch all:",
            list(await txn.fetch_all("category", {"~plaintag": "a", "enctag": "b"})),
        )

        await txn.commit()

    # Scan entries by category and (optional) tag filter)
    async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
        log("Scan result:", row)

    # test key operations in a new session
    async with store as session:
        # Create a new keypair
        key_ident = await session.create_keypair(KeyAlg.ED25519)
        log("Created key:", key_ident)

        # Fetch keypair
        key = await session.fetch_keypair(key_ident)
        log("Fetch key:", key, "\nKey params:", key.params)

        # Sign a message
        signature = await session.sign_message(key_ident, b"my message")
        log("Signature:", signature)

        # Verify signature
        verify = verify_signature(key_ident, b"my message", signature)
        log("Verify signature:", verify)

        # Pack message
        packed = await session.pack_message([key_ident], key_ident, b"my message")
        log("Packed message:", packed)

        # Unpack message
        unpacked = await session.unpack_message(packed)
        log("Unpacked message:", unpacked)

        # Remove rows by category and (optional) tag filter
        log(
            "Removed entry count:",
            await session.remove_all(
                "category",
                {"~plaintag": "a", "$and": [{"enctag": "b"}, {"enctag": "c"}]},
            ),
        )

    log("Removed store:", await store.close(remove=True))


if __name__ == "__main__":
    log("aries-askar version:", version())

    asyncio.get_event_loop().run_until_complete(basic_test())

    log("done")
