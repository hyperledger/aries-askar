from aries_askar import (
    crypto_box_seal,
    crypto_box_seal_open,
    KeyAlg,
    Key,
)


def test_crypto_box_seal():
    x25519_key = Key.generate(KeyAlg.X25519)

    msg = b"test message"
    sealed = crypto_box_seal(x25519_key, msg)
    opened = crypto_box_seal_open(x25519_key, sealed)
    assert msg == opened
