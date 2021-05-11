import base64
from typing import Union

from aries_askar import (
    KeyAlg,
    Key,
    derive_key_ecdh_es,
    derive_key_ecdh_1pu,
)


def b64_url(val: Union[str, bytes]) -> bytes:
    if isinstance(val, str):
        val = val.encode("utf-8")
    return base64.urlsafe_b64encode(val).rstrip(b"=")


def test_ecdh_es_direct():
    ephem = Key.generate(KeyAlg.P256, ephemeral=True)
    bob = Key.generate(KeyAlg.P256)
    derived = derive_key_ecdh_es(
        KeyAlg.A256GCM, ephem, bob, "A256GCM", "Alice", "Bob", receive=False
    )
    assert derived.algorithm == KeyAlg.A256GCM


def test_ecdh_1pu_direct():
    ephem = Key.generate(KeyAlg.P256, ephemeral=True)
    alice = Key.generate(KeyAlg.P256)
    bob = Key.generate(KeyAlg.P256)
    derived = derive_key_ecdh_1pu(
        KeyAlg.A256GCM,
        ephem,
        alice,
        bob,
        "A256GCM",
        "Alice",
        "Bob",
        cc_tag=None,
        receive=False,
    )
    assert derived.algorithm == KeyAlg.A256GCM


# from ECDH-1PU RFC draft 4
def test_ecdh_1pu_wrapped_expected():
    ephem = Key.from_jwk(
        """
        {"kty": "OKP",
         "crv": "X25519",
         "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
         "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}
    """
    )
    alice = Key.from_jwk(
        """
        {"kty": "OKP",
         "crv": "X25519",
         "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
         "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}
    """
    )
    bob = Key.from_jwk(
        """
        {"kty": "OKP",
         "crv": "X25519",
         "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
         "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}
    """
    )
    protected_b64 = b64_url(
        '{"alg":"ECDH-1PU+A128KW",'
        '"enc":"A256CBC-HS512",'
        '"apu":"QWxpY2U",'  # Alice
        '"apv":"Qm9iIGFuZCBDaGFybGll",'  # Bob and Charlie
        '"epk":'
        '{"kty":"OKP",'
        '"crv":"X25519",'
        '"x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}'
    )

    cek = Key.from_secret_bytes(
        KeyAlg.A256CBC_HS512,
        bytes.fromhex(
            "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0"
            "efeeedecebeae9e8e7e6e5e4e3e2e1e0"
            "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0"
            "cfcecdcccbcac9c8c7c6c5c4c3c2c1c0"
        ),
    )
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    message = b"Three is a magic number."

    enc = cek.aead_encrypt(message, iv, aad=protected_b64)
    ciphertext = enc[:-32]
    tag = enc[-32:]
    assert b64_url(ciphertext) == b"Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw"
    assert b64_url(tag) == b"HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"

    derived = derive_key_ecdh_1pu(
        KeyAlg.A128KW,
        ephem,
        sender_key=alice,
        receiver_key=bob,
        alg_id="ECDH-1PU+A128KW",
        apu="Alice",
        apv="Bob and Charlie",
        cc_tag=tag,
        receive=False,
    )
    assert derived.algorithm == KeyAlg.A128KW
    assert derived.get_secret_bytes() == bytes.fromhex(
        "df4c37a0668306a11e3d6b0074b5d8df"
    )

    encrypted_key = derived.wrap_key(cek)
    assert b64_url(encrypted_key) == (
        b"pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-"
        b"sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
    )

    # Skipping key derivation for Charlie.
    # Assemble encrypted_key, iv, cc_tag, ciphertext, and headers into a JWE envelope here.
    # Receiver disassembles envelope and..

    derived_recv = derive_key_ecdh_1pu(
        KeyAlg.A128KW,
        ephem,
        sender_key=alice,
        receiver_key=bob,
        alg_id="ECDH-1PU+A128KW",
        apu="Alice",
        apv="Bob and Charlie",
        cc_tag=tag,
        receive=True,
    )

    cek_recv = derived_recv.unwrap_key(KeyAlg.A256CBC_HS512, encrypted_key)
    assert cek_recv.get_jwk_secret() == cek.get_jwk_secret()

    enc = ciphertext + tag
    message_recv = cek_recv.aead_decrypt(enc, iv, aad=protected_b64)
    assert message_recv == message
