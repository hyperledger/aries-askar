"""Handling of Store instances."""

import json

from typing import Optional, Sequence, Union

from . import bindings

from .error import StoreError, StoreErrorCode
from .types import Entry, EntryOperation, KeyAlg, KeyEntry


class EntrySet:
    """A set of query results."""

    def __init__(self, handle: bindings.EntrySetHandle):
        """Initialize the EntrySet instance."""
        self.handle = handle

    def __iter__(self):
        return self

    def __next__(self):
        entry = bindings.entry_set_next(self.handle)
        if entry:
            # keep reference to self so the buffer isn't dropped
            entry.entry_set = self
            return entry
        else:
            raise StopIteration

    def __del__(self):
        bindings.entry_set_free(self.handle)


class Scan:
    """A scan of the Store."""

    def __init__(
        self,
        store: "Store",
        profile: Optional[str],
        category: Union[str, bytes],
        tag_filter: Union[str, dict] = None,
        offset: int = None,
        limit: int = None,
    ):
        """Initialize the Scan instance."""
        self.params = (store, profile, category, tag_filter, offset, limit)
        self.handle = None
        self.buffer: EntrySet = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.handle is None:
            (store, profile, category, tag_filter, offset, limit) = self.params
            if not store.handle:
                raise StoreError(
                    StoreErrorCode.WRAPPER, "Cannot scan from closed store"
                )
            self.handle = await bindings.scan_start(
                store.handle, profile, category, tag_filter, offset, limit
            )
            scan_handle = await bindings.scan_next(self.handle)
            self.buffer = EntrySet(scan_handle) if scan_handle else None
        while True:
            if not self.buffer:
                raise StopAsyncIteration
            row = next(self.buffer, None)
            if row:
                return row
            scan_handle = await bindings.scan_next(self.handle)
            self.buffer = EntrySet(scan_handle) if scan_handle else None

    def __del__(self):
        """Close the pool instance when there are no more references to this object."""
        if self.handle:
            bindings.scan_free(self.handle)


class Store:
    """An opened Store instance."""

    def __init__(self, handle: bindings.StoreHandle, uri: str):
        """Initialize the Store instance."""
        self.handle = handle
        self.opener = None
        self.session = None
        self.uri = uri

    @classmethod
    async def provision(
        cls,
        uri: str,
        wrap_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
        recreate: bool = False,
    ) -> "Store":
        return Store(
            await bindings.store_provision(
                uri, wrap_method, pass_key, profile, recreate
            ),
            uri,
        )

    @classmethod
    async def open(
        cls,
        uri: str,
        wrap_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
    ) -> "Store":
        return Store(
            await bindings.store_open(uri, wrap_method, pass_key, profile), uri
        )

    @classmethod
    async def remove(cls, uri: str) -> bool:
        return await bindings.store_remove(uri)

    async def __aenter__(self) -> "Session":
        if not self.opener:
            self.opener = OpenSession(self, None, False)
        return await self.opener.__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        return await self.opener.__aexit__(exc_type, exc, tb)

    async def create_profile(self, name: str = None) -> str:
        return await bindings.store_create_profile(self.handle, name)

    async def get_profile_name(self) -> str:
        return await bindings.store_get_profile_name(self.handle)

    async def remove_profile(self, name: str) -> bool:
        return await bindings.store_remove_profile(self.handle, name)

    async def rekey(
        self,
        wrap_method: str = None,
        pass_key: str = None,
    ):
        await bindings.store_rekey(self.handle, wrap_method, pass_key)

    def scan(
        self,
        category: str,
        tag_filter: Union[str, dict] = None,
        offset: int = None,
        limit: int = None,
        profile: str = None,
    ) -> Scan:
        return Scan(self, profile, category, tag_filter, offset, limit)

    def session(self, profile: str = None) -> "OpenSession":
        return OpenSession(self, profile, False)

    def transaction(self, profile: str = None) -> "OpenSession":
        return OpenSession(self, profile, True)

    async def close(self, remove: bool = False) -> bool:
        """Close and free the pool instance."""
        if self.handle:
            await bindings.store_close(self.handle)
            self.handle = None
        if remove:
            return await Store.remove(self.uri)
        else:
            return False

    def __del__(self):
        """Close the pool instance when there are no more references to this object."""
        if self.handle:
            bindings.store_close_immed(self.handle)

    def __repr__(self) -> str:
        return f"<Store(handle={self.handle})>"


class Session:
    """An opened Session instance."""

    def __init__(self, handle: bindings.SessionHandle, is_txn: bool):
        """Initialize the Session instance."""
        self.handle = handle
        self.is_txn = is_txn

    async def count(self, category: str, tag_filter: Union[str, dict] = None) -> int:
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot count from closed session")
        return await bindings.session_count(self.handle, category, tag_filter)

    async def fetch(
        self, category: str, name: str, *, for_update: bool = False
    ) -> Optional[Entry]:
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot fetch from closed session")
        result_handle = await bindings.session_fetch(
            self.handle, category, name, for_update
        )
        return next(EntrySet(result_handle), None) if result_handle else None

    async def fetch_all(
        self,
        category: str,
        tag_filter: Union[str, dict] = None,
        limit: int = None,
        *,
        for_update: bool = False,
    ) -> Sequence[Entry]:
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot fetch from closed session")
        return list(
            EntrySet(
                await bindings.session_fetch_all(
                    self.handle, category, tag_filter, limit, for_update
                )
            )
        )

    async def insert(
        self,
        category: str,
        name: str,
        value: Union[str, bytes, memoryview] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self.handle, EntryOperation.INSERT, category, name, value, tags, expiry_ms
        )

    async def replace(
        self,
        category: str,
        name: str,
        value: Union[str, bytes, memoryview] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self.handle, EntryOperation.REPLACE, category, name, value, tags, expiry_ms
        )

    async def remove(
        self,
        category: str,
        name: str,
    ):
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot update closed session")
        await bindings.session_update(
            self.handle, EntryOperation.REMOVE, category, name
        )

    async def remove_all(
        self,
        category: str,
        tag_filter: Union[str, dict] = None,
    ) -> int:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot remove all for closed session"
            )
        return await bindings.session_remove_all(self.handle, category, tag_filter)

    async def create_keypair(
        self,
        key_alg: KeyAlg,
        *,
        metadata: str = None,
        tags: dict = None,
        seed: Union[str, bytes, memoryview] = None,
    ) -> str:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot create keypair with closed session"
            )
        return str(
            await bindings.session_create_keypair(
                self.handle, key_alg.value, metadata, tags, seed
            )
        )

    async def fetch_keypair(
        self, ident: str, *, for_update: bool = False
    ) -> Optional[KeyEntry]:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot fetch keypair from closed session"
            )
        handle = await bindings.session_fetch_keypair(self.handle, ident, for_update)
        if handle:
            entry = next(EntrySet(handle))
            result = KeyEntry(entry.category, entry.name, entry.value_json, entry.tags)
            return result

    async def update_keypair(
        self,
        ident: str,
        *,
        metadata: str = None,
        tags: dict = None,
    ):
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot update keypair with closed session"
            )
        await bindings.session_update_keypair(self.handle, ident, metadata, tags)

    async def sign_message(
        self, key_ident: str, message: Union[str, bytes, memoryview]
    ) -> bytes:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot sign message with closed session"
            )
        buf = await bindings.session_sign_message(self.handle, key_ident, message)
        return bytes(buf)

    async def pack_message(
        self,
        recipient_vks: Sequence[str],
        from_key_ident: Optional[str],
        message: Union[str, bytes, memoryview],
    ) -> bytes:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot pack message with closed session"
            )
        return bytes(
            await bindings.session_pack_message(
                self.handle, recipient_vks, from_key_ident, message
            )
        )

    async def unpack_message(
        self,
        message: Union[str, bytes, memoryview],
    ) -> (bytes, str, Optional[str]):
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot unpack message with closed session"
            )
        (unpacked, recip, sender) = await bindings.session_unpack_message(
            self.handle, message
        )
        return (bytes(unpacked), recip, sender)

    async def commit(self):
        if not self.is_txn:
            raise StoreError(StoreErrorCode.WRAPPER, "Session is not a transaction")
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot commit closed transaction")
        await bindings.session_close(self.handle, True)
        self.handle = None

    async def rollback(self):
        if not self.is_txn:
            raise StoreError(StoreErrorCode.WRAPPER, "Session is not a transaction")
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot rollback closed transaction"
            )
        await bindings.session_close(self.handle, False)
        self.handle = None

    async def close(self):
        if self.handle:
            await bindings.session_close(self.handle, False)
            self.handle = None

    def __del__(self):
        if self.handle:
            bindings.session_close_immed(self.handle)
            self.handle = None

    def __repr__(self) -> str:
        return f"<Session(handle={self.handle}, is_txn={self.is_txn})>"


async def _open_session(handle, profile, is_txn) -> Session:
    return Session(
        await bindings.session_start(handle, profile, is_txn),
        is_txn,
    )


class OpenSession:
    def __init__(self, store: Store, profile: Optional[str], is_txn: bool):
        """Initialize the OpenSession instance."""
        self.store = store
        self.profile = profile
        self.is_txn = is_txn
        self.session = None

    def __await__(self) -> "Session":
        if not self.store.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot start session from closed store"
            )
        return _open_session(self.store.handle, self.profile, self.is_txn).__await__()

    async def __aenter__(self) -> "Session":
        if self.session:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot re-enter session opener")
        self.session = await _open_session(self.store.handle, self.profile, self.is_txn)
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        await self.session.close()
        self.session = None
