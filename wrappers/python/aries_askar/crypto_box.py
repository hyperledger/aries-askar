from typing import Union

from . import bindings
from .key import Key


def random_nonce() -> bytes:
    return bytes(bindings.key_crypto_box_random_nonce())


def crypto_box(
    receiver_key: Key,
    sender_key: Key,
    message: Union[bytes, str],
    nonce: bytes,
) -> bytes:
    return bytes(
        bindings.key_crypto_box(
            receiver_key._handle, sender_key._handle, message, nonce
        )
    )


def crypto_box_open(
    receiver_key: Key,
    sender_key: Key,
    message: Union[bytes, str],
    nonce: bytes,
) -> bytes:
    return bytes(
        bindings.key_crypto_box_open(
            receiver_key._handle, sender_key._handle, message, nonce
        )
    )


def crypto_box_seal(
    receiver_key: Key,
    message: Union[bytes, str],
) -> bytes:
    return bytes(bindings.key_crypto_box_seal(receiver_key._handle, message))


def crypto_box_seal_open(
    receiver_key: Key,
    ciphertext: bytes,
) -> bytes:
    return bytes(bindings.key_crypto_box_seal_open(receiver_key._handle, ciphertext))
