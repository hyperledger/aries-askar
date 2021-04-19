import asyncio
import logging
import os
import sys
from aries_askar import bindings

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

ENCRYPT = True


def log(*args):
    print(*args, "\n")


async def basic_test():
    if ENCRYPT:
        key = generate_raw_key(b"00000000000000000000000000000My1")
        key_method = "raw"
        log("Generated raw store key:", key)
    else:
        key = None
        key_method = "none"

    # Provision the store
    store = await Store.provision(REPO_URI, key_method, key, recreate=True)
    log("Provisioned store:", store)
    log("Profile name:", await store.get_profile_name())

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
            await txn.fetch_all("category", {"~plaintag": "a", "enctag": "b"}),
        )

        await txn.commit()

    # Scan entries by category and (optional) tag filter)
    async for row in store.scan("category", {"~plaintag": "a", "enctag": "b"}):
        log("Scan result:", row)

    key = bindings.key_generate("ed25519")
    log("Created key:", key)

    log("Key algorithm:", bindings.key_get_algorithm(key))

    jwk = bindings.key_get_jwk_public(key)
    log("JWK:", jwk)

    key = bindings.key_generate("aes256gcm")
    log("Key algorithm:", bindings.key_get_algorithm(key))

    data = b"test message"
    nonce = bindings.key_aead_random_nonce(key)
    enc = bindings.key_aead_encrypt(key, data, nonce, b"aad")
    dec = bindings.key_aead_decrypt(key, enc, nonce, b"aad")
    assert data == bytes(dec)

    # test key operations in a new session
    async with store as session:
        # # Create a new keypair
        # key_ident = await session.create_keypair(KeyAlg.ED25519, metadata="metadata")
        # log("Created key:", key_ident)

        # # Update keypair
        # await session.update_keypair(key_ident, metadata="updated metadata")
        # log("Updated key")

        # # Fetch keypair
        # key = await session.fetch_keypair(key_ident)
        # log("Fetch key:", key, "\nKey params:", key.params)

        # # Sign a message
        # signature = await session.sign_message(key_ident, b"my message")
        # log("Signature:", signature)

        # # Verify signature
        # verify = await verify_signature(key_ident, b"my message", signature)
        # log("Verify signature:", verify)

        # Remove rows by category and (optional) tag filter
        log(
            "Removed entry count:",
            await session.remove_all(
                "category",
                {"~plaintag": "a", "$and": [{"enctag": "b"}, {"enctag": "c"}]},
            ),
        )

    profile = await store.create_profile()
    log("Created profile:", profile)
    log("Removed profile:", await store.remove_profile(profile))

    key2 = generate_raw_key(b"00000000000000000000000000000My2")
    await store.rekey("raw", key2)
    log("Re-keyed store")

    log("Removed store:", await store.close(remove=True))


if __name__ == "__main__":
    log("aries-askar version:", version())

    asyncio.get_event_loop().run_until_complete(basic_test())

    log("done")
