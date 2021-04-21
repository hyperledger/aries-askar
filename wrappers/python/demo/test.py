import asyncio
import logging
import os
import sys

from aries_askar.bindings import (
    generate_raw_key,
    version,
)
from aries_askar import KeyAlg, Key, Store, derive_key_ecdh_es, derive_key_ecdh_1pu

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


def keys_test():

    key = Key.generate(KeyAlg.ED25519)
    log("Created key:", key)
    message = b"test message"
    sig = key.sign_message(message)
    log("Signature:", sig)
    verify = key.verify_signature(message, sig)
    log("Verify:", verify)

    log("Key algorithm:", key.algorithm)

    jwk = key.get_jwk_public()
    log("JWK:", jwk)

    key = Key.generate(KeyAlg.AES128GCM)
    log("Key algorithm:", key.algorithm)

    data = b"test message"
    nonce = key.aead_random_nonce()
    enc = key.aead_encrypt(data, nonce, b"aad")
    dec = key.aead_decrypt(enc, nonce, b"aad")
    assert data == bytes(dec)

    ephem = Key.generate(KeyAlg.P256, ephemeral=True)
    alice = Key.generate(KeyAlg.P256)
    bob = Key.generate(KeyAlg.P256)
    derived = derive_key_ecdh_1pu("A256GCM", ephem, alice, bob, "Alice", "Bob")
    log("Derived:", derived.get_jwk_thumbprint())
    # derived = bindings.key_derive_ecdh_1pu("a256gcm", ephem, alice, bob, "Alice", "Bob")
    # log("Derived:", bindings.key_get_jwk_thumbprint(derived))
    # derived = bindings.key_derive_ecdh_es("a256gcm", ephem, bob, "Alice", "Bob")
    # log("Derived:", bindings.key_get_jwk_thumbprint(derived))
    derived = derive_key_ecdh_es("A256GCM", ephem, bob, "Alice", "Bob")
    log("Derived:", derived.get_jwk_thumbprint())


async def store_test():
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

    keys_test()
    asyncio.get_event_loop().run_until_complete(store_test())

    log("done")
