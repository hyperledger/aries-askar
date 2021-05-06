import asyncio
import logging
import os
import sys

from aries_askar.bindings import (
    generate_raw_key,
    version,
)
from aries_askar import (
    KeyAlg,
    Key,
    Store,
    crypto_box_seal,
    crypto_box_seal_open,
    derive_key_ecdh_es,
    derive_key_ecdh_1pu,
)

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
    x25519_key = key.convert_key(KeyAlg.X25519)
    log("Converted key:", x25519_key)

    x25519_key_2 = Key.generate(KeyAlg.X25519)
    kex = x25519_key.key_exchange(KeyAlg.XC20P, x25519_key_2)
    log("Key exchange:", kex)

    msg = b"test message"
    sealed = crypto_box_seal(x25519_key, msg)
    opened = crypto_box_seal_open(x25519_key, sealed)
    assert msg == opened

    log("Key algorithm:", key.algorithm)

    jwk = key.get_jwk_public()
    log("JWK:", jwk)

    key = Key.generate(KeyAlg.AES128GCM)
    log("Key algorithm:", key.algorithm)

    data = b"test message"
    nonce = key.aead_random_nonce()
    params = key.aead_params()
    assert params.nonce_length == 12
    assert params.tag_length == 16
    enc = key.aead_encrypt(data, nonce, b"aad")
    dec = key.aead_decrypt(enc, nonce, b"aad")
    assert data == bytes(dec)

    ephem = Key.generate(KeyAlg.P256, ephemeral=True)
    alice = Key.generate(KeyAlg.P256)
    bob = Key.generate(KeyAlg.P256)
    derived = derive_key_ecdh_1pu("A256GCM", ephem, alice, bob, "Alice", "Bob")
    log("Derived:", derived.get_jwk_thumbprint())
    derived = derive_key_ecdh_es("A256GCM", ephem, bob, "Alice", "Bob")
    log("Derived:", derived.get_jwk_thumbprint())

    key = Key.from_seed(KeyAlg.BLS12_381_G1G2, b"testseed000000000000000000000001")
    log("BLS key G1:", key.get_jwk_public(KeyAlg.BLS12_381_G1))
    log("BLS key G2:", key.get_jwk_public(KeyAlg.BLS12_381_G2))
    log("BLS key G1G2:", key.get_jwk_public())


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
        # Create a new keypair
        keypair = Key.generate(KeyAlg.ED25519)
        log("Created key:", keypair)

        # Store keypair
        key_name = "testkey"
        await session.insert_key(key_name, keypair, metadata="metadata")
        log("Inserted key")

        # Update keypair
        await session.update_key(key_name, metadata="updated metadata", tags={"a": "b"})
        log("Updated key")

        # Fetch keypair
        fetch_key = await session.fetch_key(key_name)
        log("Fetched key:", fetch_key)
        thumbprint = keypair.get_jwk_thumbprint()
        assert fetch_key.key.get_jwk_thumbprint() == thumbprint

        # Fetch with filters
        keys = await session.fetch_all_keys(
            alg=KeyAlg.ED25519, thumbprint=thumbprint, tag_filter={"a": "b"}, limit=1
        )
        log("Fetched keys:", keys)
        assert len(keys) == 1

    async with store as session:
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
