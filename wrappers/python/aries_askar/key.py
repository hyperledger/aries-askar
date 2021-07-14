"""Handling of Key instances."""

from typing import Union

from . import bindings

from .bindings import Encrypted
from .types import KeyAlg, SeedMethod


class Key:
    """An active key or keypair instance."""

    def __init__(self, handle: bindings.LocalKeyHandle):
        """Initialize the Key instance."""
        self._handle = handle

    @classmethod
    def generate(cls, alg: Union[str, KeyAlg], *, ephemeral: bool = False) -> "Key":
        return cls(bindings.key_generate(alg, ephemeral))

    @classmethod
    def from_seed(
        cls,
        alg: Union[str, KeyAlg],
        seed: Union[str, bytes],
        *,
        method: Union[str, SeedMethod] = None,
    ) -> "Key":
        return cls(bindings.key_from_seed(alg, seed, method))

    @classmethod
    def from_secret_bytes(cls, alg: Union[str, KeyAlg], secret: bytes) -> "Key":
        return cls(bindings.key_from_secret_bytes(alg, secret))

    @classmethod
    def from_public_bytes(cls, alg: Union[str, KeyAlg], public: bytes) -> "Key":
        return cls(bindings.key_from_public_bytes(alg, public))

    @classmethod
    def from_jwk(cls, jwk: Union[dict, str, bytes]) -> "Key":
        return cls(bindings.key_from_jwk(jwk))

    @property
    def handle(self) -> bindings.LocalKeyHandle:
        """Accessor for the key handle."""
        return self._handle

    @property
    def algorithm(self) -> KeyAlg:
        alg = bindings.key_get_algorithm(self._handle)
        return KeyAlg.from_key_alg(alg)

    @property
    def ephemeral(self) -> "Key":
        return bindings.key_get_ephemeral(self._handle)

    def convert_key(self, alg: Union[str, KeyAlg]) -> "Key":
        return self.__class__(bindings.key_convert(self._handle, alg))

    def key_exchange(self, alg: Union[str, KeyAlg], pk: "Key") -> "Key":
        return self.__class__(bindings.key_exchange(alg, self._handle, pk._handle))

    def get_public_bytes(self) -> bytes:
        return bytes(bindings.key_get_public_bytes(self._handle))

    def get_secret_bytes(self) -> bytes:
        return bytes(bindings.key_get_secret_bytes(self._handle))

    def get_jwk_public(self, alg: Union[str, KeyAlg] = None) -> str:
        return bindings.key_get_jwk_public(self._handle, alg)

    def get_jwk_secret(self) -> str:
        return str(bindings.key_get_jwk_secret(self._handle))

    def get_jwk_thumbprint(self, alg: Union[str, KeyAlg] = None) -> str:
        return bindings.key_get_jwk_thumbprint(self._handle, alg)

    def aead_params(self) -> bindings.AeadParams:
        return bindings.key_aead_get_params(self._handle)

    def aead_random_nonce(self) -> bytes:
        return bytes(bindings.key_aead_random_nonce(self._handle))

    def aead_encrypt(
        self, message: Union[str, bytes], *, nonce: bytes = None, aad: bytes = None
    ) -> Encrypted:
        return bindings.key_aead_encrypt(self._handle, message, nonce, aad)

    def aead_decrypt(
        self,
        ciphertext: Union[bytes, Encrypted],
        *,
        nonce: bytes,
        tag: bytes = None,
        aad: bytes = None,
    ) -> bytes:
        return bytes(
            bindings.key_aead_decrypt(self._handle, ciphertext, nonce, tag, aad)
        )

    def sign_message(self, message: Union[str, bytes], sig_type: str = None) -> bytes:
        return bytes(bindings.key_sign_message(self._handle, message, sig_type))

    def verify_signature(
        self, message: Union[str, bytes], signature: bytes, sig_type: str = None
    ) -> bool:
        return bindings.key_verify_signature(self._handle, message, signature, sig_type)

    def wrap_key(self, other: "Key", *, nonce: bytes = None) -> Encrypted:
        return bindings.key_wrap_key(self._handle, other._handle, nonce)

    def unwrap_key(
        self,
        alg: Union[str, KeyAlg],
        ciphertext: Union[bytes, Encrypted],
        *,
        nonce: bytes = None,
        tag: bytes = None,
    ) -> "Key":
        return Key(bindings.key_unwrap_key(self._handle, alg, ciphertext, nonce, tag))

    def __repr__(self) -> str:
        return (
            f"<Key(handle={self._handle}, alg={self.algorithm}, "
            f"ephemeral={self.ephemeral})>"
        )
