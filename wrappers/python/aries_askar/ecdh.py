from typing import Optional, Union

from .bindings import Encrypted, key_derive_ecdh_es, key_derive_ecdh_1pu
from .key import Key
from .types import KeyAlg


def _load_key(key: Union[dict, str, Key]) -> Key:
    if isinstance(key, (str, dict)):
        key = Key.from_jwk(key)
    return key


class EcdhEs:
    def __init__(
        self,
        alg_id: Union[bytes, str],
        apu: Union[bytes, str],
        apv: Union[bytes, str],
    ):
        self._params = (alg_id, apu, apv)

    def _derive_key(
        self,
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Key,
        receiver_key: Key,
        receive: bool,
    ) -> Key:
        return Key(
            key_derive_ecdh_es(
                enc_alg,
                ephemeral_key._handle,
                receiver_key._handle,
                *self._params,
                receive,
            )
        )

    def encrypt_direct(
        self,
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        message: Union[str, bytes],
        *,
        aad: bytes = None,
        nonce: bytes = None,
    ) -> Encrypted:
        derived = self._derive_key(
            enc_alg, _load_key(ephemeral_key), _load_key(receiver_key), False
        )
        return derived.aead_encrypt(message, nonce=nonce, aad=aad)

    def decrypt_direct(
        self,
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        ciphertext: bytes,
        *,
        nonce: bytes,
        tag: bytes,
        aad: bytes = None,
    ) -> bytes:
        derived = self._derive_key(
            enc_alg, _load_key(ephemeral_key), _load_key(receiver_key), True
        )
        return derived.aead_decrypt(ciphertext, nonce=nonce, tag=tag, aad=aad)

    def sender_wrap_key(
        self,
        wrap_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        cek: Key,
    ) -> Encrypted:
        derived = self._derive_key(
            wrap_alg, _load_key(ephemeral_key), _load_key(receiver_key), False
        )
        return derived.wrap_key(cek)

    def receiver_unwrap_key(
        self,
        wrap_alg: Union[str, KeyAlg],
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        ciphertext: bytes,
        *,
        nonce: bytes = None,
        tag: bytes = None,
    ) -> Key:
        derived = self._derive_key(
            wrap_alg, _load_key(ephemeral_key), _load_key(receiver_key), True
        )
        return derived.unwrap_key(enc_alg, ciphertext, nonce=nonce, tag=tag)


class Ecdh1PU:
    def __init__(
        self,
        alg_id: Union[bytes, str],
        apu: Union[bytes, str],
        apv: Union[bytes, str],
    ):
        self._params = (alg_id, apu, apv)

    def _derive_key(
        self,
        key_alg: Union[str, KeyAlg],
        ephemeral_key: Key,
        sender_key: Key,
        receiver_key: Key,
        cc_tag: Optional[bytes],
        receive: bool,
    ) -> Key:
        return Key(
            key_derive_ecdh_1pu(
                key_alg,
                ephemeral_key._handle,
                sender_key._handle,
                receiver_key._handle,
                *self._params,
                cc_tag,
                receive,
            )
        )

    def encrypt_direct(
        self,
        key_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        sender_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        message: Union[str, bytes],
        *,
        aad: bytes = None,
        nonce: bytes = None,
    ) -> Encrypted:
        derived = self._derive_key(
            key_alg,
            _load_key(ephemeral_key),
            _load_key(sender_key),
            _load_key(receiver_key),
            None,
            False,
        )
        return derived.aead_encrypt(message, nonce=nonce, aad=aad)

    def decrypt_direct(
        self,
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        sender_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        ciphertext: bytes,
        *,
        nonce: bytes,
        tag: bytes,
        aad: bytes = None,
    ) -> bytes:
        derived = self._derive_key(
            enc_alg,
            _load_key(ephemeral_key),
            _load_key(sender_key),
            _load_key(receiver_key),
            None,
            True,
        )
        return derived.aead_decrypt(ciphertext, nonce=nonce, tag=tag, aad=aad)

    def sender_wrap_key(
        self,
        wrap_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        sender_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        cek: Key,
        *,
        cc_tag: bytes,
    ) -> Encrypted:
        derived = self._derive_key(
            wrap_alg,
            _load_key(ephemeral_key),
            _load_key(sender_key),
            _load_key(receiver_key),
            cc_tag=cc_tag,
            receive=False,
        )
        return derived.wrap_key(cek)

    def receiver_unwrap_key(
        self,
        wrap_alg: Union[str, KeyAlg],
        enc_alg: Union[str, KeyAlg],
        ephemeral_key: Union[dict, str, Key],
        sender_key: Union[dict, str, Key],
        receiver_key: Union[dict, str, Key],
        ciphertext: bytes,
        *,
        cc_tag: bytes,
        nonce: bytes = None,
        tag: bytes = None,
    ) -> Key:
        derived = self._derive_key(
            wrap_alg,
            _load_key(ephemeral_key),
            _load_key(sender_key),
            _load_key(receiver_key),
            cc_tag=cc_tag,
            receive=True,
        )
        return derived.unwrap_key(enc_alg, ciphertext, nonce=nonce, tag=tag)
