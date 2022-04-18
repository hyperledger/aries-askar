import base64
from typing import Union

from aries_askar import (
    KeyAlg,
    Key,
)
from aries_askar.ecdh import EcdhEs, Ecdh1PU


def b64_url(val: Union[str, bytes]) -> str:
    if isinstance(val, str):
        val = val.encode("utf-8")
    return base64.urlsafe_b64encode(val).rstrip(b"=").decode("ascii")


def test_ecdh_es_direct():
    bob_key = Key.generate(KeyAlg.P256)
    bob_jwk = bob_key.get_jwk_public()
    ephem_key = Key.generate(KeyAlg.P256)
    ephem_jwk = ephem_key.get_jwk_public()
    message = b"Hello there"
    alg = "ECDH-ES"
    enc = "A256GCM"
    apu = "Alice"
    apv = "Bob"
    protected_b64 = b64_url(
        f'{{"alg":"{alg}",'
        f'"enc":"{enc}",'
        f'"apu":"{b64_url(apu)}",'
        f'"apv":"{b64_url(apv)}",'
        f'"epk":{ephem_jwk}}}'
    ).encode("ascii")
    encrypted_msg = EcdhEs(enc, apu, apv).encrypt_direct(
        KeyAlg.A256GCM, ephem_key, bob_jwk, message, aad=protected_b64
    )
    ciphertext, tag, nonce = encrypted_msg.parts

    # switch to receiver

    message_recv = EcdhEs(enc, apu, apv).decrypt_direct(
        KeyAlg.A256GCM,
        ephem_jwk,
        bob_key,
        ciphertext,
        nonce=nonce,
        tag=tag,
        aad=protected_b64,
    )
    assert message_recv == message


def test_ecdh_es_wrapped():
    bob_key = Key.generate(KeyAlg.X25519)
    bob_jwk = bob_key.get_jwk_public()
    ephem_key = Key.generate(KeyAlg.X25519)
    ephem_jwk = ephem_key.get_jwk_public()
    message = b"Hello there"
    alg = "ECDH-ES+A128KW"
    enc = "A256GCM"
    apu = "Alice"
    apv = "Bob"
    protected_b64 = b64_url(
        f'{{"alg":"{alg}",'
        f'"enc":"{enc}",'
        f'"apu":"{b64_url(apu)}",'
        f'"apv":"{b64_url(apv)}",'
        f'"epk":{ephem_jwk}}}'
    ).encode("ascii")
    cek = Key.generate(KeyAlg.A256GCM)
    encrypted_msg = cek.aead_encrypt(message, aad=protected_b64)
    ciphertext, tag, nonce = encrypted_msg.parts
    encrypted_key = EcdhEs(alg, apu, apv).sender_wrap_key(
        KeyAlg.A128KW, ephem_key, bob_jwk, cek
    )
    encrypted_key = encrypted_key.ciphertext

    # switch to receiver

    cek_recv = EcdhEs(alg, apu, apv).receiver_unwrap_key(
        KeyAlg.A128KW,
        KeyAlg.A256GCM,
        ephem_jwk,
        bob_key,
        encrypted_key,
    )
    message_recv = cek_recv.aead_decrypt(
        ciphertext, nonce=nonce, tag=tag, aad=protected_b64
    )
    assert message_recv == message


def test_ecdh_1pu_direct():
    alice_key = Key.generate(KeyAlg.P256)
    alice_jwk = alice_key.get_jwk_public()
    bob_key = Key.generate(KeyAlg.P256)
    bob_jwk = bob_key.get_jwk_public()
    ephem_key = Key.generate(KeyAlg.P256)
    ephem_jwk = ephem_key.get_jwk_public()
    message = b"Hello there"
    alg = "ECDH-1PU"
    enc = "A256GCM"
    apu = "Alice"
    apv = "Bob"
    protected_b64 = b64_url(
        f'{{"alg":"{alg}",'
        f'"enc":"{enc}",'
        f'"apu":"{b64_url(apu)}",'
        f'"apv":"{b64_url(apv)}",'
        f'"epk":{ephem_jwk}}}'
    ).encode("ascii")
    encrypted_msg = Ecdh1PU(enc, apu, apv).encrypt_direct(
        KeyAlg.A256GCM, ephem_key, alice_key, bob_jwk, message, aad=protected_b64
    )
    ciphertext, tag, nonce = encrypted_msg.parts

    # switch to receiver

    message_recv = Ecdh1PU(enc, apu, apv).decrypt_direct(
        KeyAlg.A256GCM,
        ephem_jwk,
        alice_jwk,
        bob_key,
        ciphertext,
        nonce=nonce,
        tag=tag,
        aad=protected_b64,
    )
    assert message_recv == message


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

    alg = "ECDH-1PU+A128KW"
    enc = "A256CBC-HS512"
    apu = "Alice"
    apv = "Bob and Charlie"
    protected_b64 = b64_url(
        f'{{"alg":"{alg}",'
        f'"enc":"{enc}",'
        f'"apu":"{b64_url(apu)}",'
        f'"apv":"{b64_url(apv)}",'
        '"epk":'
        '{"kty":"OKP",'
        '"crv":"X25519",'
        '"x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}'
    ).encode("ascii")
    protected = (
        f'{{"alg":"{alg}",'
        f'"enc":"{enc}",'
        f'"apu":"{b64_url(apu)}",'
        f'"apv":"{b64_url(apv)}",'
        '"epk":'
        '{"kty":"OKP",'
        '"crv":"X25519",'
        '"x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}'
    )

    assert protected == (
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

    enc = cek.aead_encrypt(message, nonce=iv, aad=protected_b64)
    ciphertext, cc_tag = enc.ciphertext, enc.tag
    assert b64_url(ciphertext) == "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw"
    assert b64_url(cc_tag) == "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"

    derived = Ecdh1PU(alg, apu, apv)._derive_key(
        KeyAlg.A128KW,
        ephem,
        sender_key=alice,
        receiver_key=bob,
        cc_tag=cc_tag,
        receive=False,
    )
    assert derived.get_secret_bytes() == bytes.fromhex(
        "df4c37a0668306a11e3d6b0074b5d8df"
    )

    encrypted_key = derived.wrap_key(cek).ciphertext_tag
    assert b64_url(encrypted_key) == (
        "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-"
        "sjNXH8-LIRLycq8CHJQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
    )

    # test sender_wrap_key
    encrypted_key_2 = Ecdh1PU(alg, apu, apv).sender_wrap_key(
        KeyAlg.A128KW,
        ephem,
        alice,
        bob,
        cek,
        cc_tag=cc_tag,
    )
    assert encrypted_key_2.ciphertext_tag == encrypted_key

    # Skipping key derivation for Charlie.
    # Assemble encrypted_key, iv, cc_tag, ciphertext, and headers into a JWE envelope here.
    # Receiver disassembles envelope and..

    derived_recv = Ecdh1PU(alg, apu, apv)._derive_key(
        KeyAlg.A128KW,
        ephem,
        sender_key=alice,
        receiver_key=bob,
        cc_tag=cc_tag,
        receive=True,
    )

    cek_recv = derived_recv.unwrap_key(KeyAlg.A256CBC_HS512, encrypted_key)
    assert cek_recv.get_jwk_secret() == cek.get_jwk_secret()

    message_recv = cek_recv.aead_decrypt(
        ciphertext, nonce=iv, aad=protected_b64, tag=cc_tag
    )
    assert message_recv == message

    # test receiver_wrap_key
    cek_recv_2 = Ecdh1PU(alg, apu, apv).receiver_unwrap_key(
        KeyAlg.A128KW,
        KeyAlg.A256CBC_HS512,
        ephem,
        sender_key=alice,
        receiver_key=bob,
        ciphertext=encrypted_key,
        cc_tag=cc_tag,
    )
    assert cek_recv_2.get_jwk_secret() == cek.get_jwk_secret()
