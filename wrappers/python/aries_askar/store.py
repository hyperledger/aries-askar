"""Handling of Store instances."""

import asyncio
import json

from typing import Optional, Sequence

from . import bindings

from .error import StoreError, StoreErrorCode
from .types import Entry, KeyAlg, KeyEntry, UpdateEntry


class EntrySet:
    """A set of query results."""

    def __init__(self, handle: bindings.EntrySetHandle):
        """Initialize the EntrySet instance."""
        self.handle = handle

    def __iter__(self):
        return self

    def __next__(self):
        entry = bindings.store_results_next(self.handle)
        if entry:
            return entry
        else:
            raise StopIteration

    def __del__(self):
        bindings.store_results_free(self.handle)


class Scan:
    """A scan of the Store."""

    def __init__(
        self, store: "Store", category: [str, bytes], tag_filter: [str, dict] = None
    ):
        """Initialize the Scan instance."""
        self.params = (store, category, tag_filter)
        self.handle = None
        self.buffer: EntrySet = None

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.handle is None:
            if not self.params:
                raise StoreError(StoreErrorCode.WRAPPER, "Cannot reuse scan")
            (store, category, tag_filter) = self.params
            self.params = None
            if not store.handle:
                raise StoreError(
                    StoreErrorCode.WRAPPER, "Cannot scan from closed store"
                )
            self.handle = await bindings.store_scan_start(
                store.handle, category, tag_filter
            )
            scan_handle = await bindings.store_scan_next(self.handle)
            self.buffer = EntrySet(scan_handle) if scan_handle else None
        while True:
            if not self.buffer:
                raise StopAsyncIteration
            row = next(self.buffer, None)
            if row:
                return row
            scan_handle = await bindings.store_scan_next(self.handle)
            self.buffer = EntrySet(scan_handle) if scan_handle else None

    def __del__(self):
        """Close the pool instance when there are no more references to this object."""
        if self.handle:
            bindings.store_scan_free(self.handle)


class Lock:
    """An entry lock on a Store."""

    def __init__(
        self, store: "Store", lock_info: UpdateEntry, acquire_timeout_ms: int = None
    ):
        """Initialize the Lock instance."""
        self.handle = None
        self._entry: Entry = None
        self._new_record: bool = None
        self.params = (store, lock_info, acquire_timeout_ms)

    async def _acquire(self):
        if not self.params:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot reuse lock instance")
        (store, lock_info, timeout) = self.params
        self.params = None
        if not store.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot create lock with closed store"
            )
        self.handle = await bindings.store_create_lock(store.handle, lock_info, timeout)
        (self._entry, self._new_record) = bindings.store_lock_get_result(self.handle)

    def __await__(self):
        yield from self._acquire().__await__()
        return self

    async def __aenter__(self):
        await self._acquire()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        pass

    @property
    def entry(self) -> Entry:
        return self._entry

    @property
    def new_record(self) -> bool:
        return self._new_record

    async def update(self, entries: Sequence[UpdateEntry]):
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Lock must be acquired using `async with`"
            )
        await bindings.store_lock_update(self.handle, entries)

    def __del__(self):
        if self.handle:
            bindings.store_lock_free(self.handle)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(handle={self.handle}, "
            f"entry={self._entry}, new_record={self._new_record})"
        )


class Store:
    """An opened Store instance."""

    def __init__(self, handle: bindings.StoreHandle):
        """Initialize the Store instance."""
        self.handle = handle

    @classmethod
    def provision(
        cls, uri: str, wrap_method: str = None, pass_key: str = None
    ) -> "StoreOpen":
        return StoreOpen(bindings.store_provision(uri, wrap_method, pass_key))

    @classmethod
    def open(cls, uri: str, pass_key: str = None) -> "StoreOpen":
        return StoreOpen(bindings.store_open(uri, pass_key))

    async def close(self):
        """Close and free the pool instance."""
        if self.handle:
            await bindings.store_close(self.handle)
            self.handle = None

    def __del__(self):
        """Close the pool instance when there are no more references to this object."""
        if self.handle:
            bindings.store_close_immed(self.handle)

    async def count(self, category: str, tag_filter: [str, dict] = None) -> int:
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot count from closed store")
        return await bindings.store_count(self.handle, category, tag_filter)

    async def fetch(self, category: str, name: str) -> Optional[Entry]:
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot fetch from closed store")
        result_handle = await bindings.store_fetch(self.handle, category, name)
        return next(EntrySet(result_handle), None) if result_handle else None

    def scan(self, category: str, tag_filter: [str, dict] = None) -> Scan:
        return Scan(self, category, tag_filter)

    async def update(self, entries: Sequence[UpdateEntry]):
        if not self.handle:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot update closed store")
        await bindings.store_update(self.handle, entries)

    def create_lock(
        self,
        category: str,
        name: str,
        value: [str, bytes] = None,
        tags: dict = None,
        expire_ms: int = None,
        acquire_timeout_ms: int = None,
        json=None,
    ) -> Lock:
        lock_info = UpdateEntry(
            category,
            name,
            json=json,
            value=value,
            tags=tags,
            expire_ms=expire_ms,
        )
        return Lock(self, lock_info, acquire_timeout_ms)

    async def create_keypair(
        self, key_alg: KeyAlg, metadata: str = None, seed: [str, bytes] = None
    ) -> str:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot create keypair with closed store"
            )
        return str(
            await bindings.store_create_keypair(
                self.handle, key_alg.value, metadata, seed
            )
        )

    async def fetch_keypair(self, ident: str) -> Optional[KeyEntry]:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot fetch keypair from closed store"
            )
        handle = await bindings.store_fetch_keypair(self.handle, ident)
        if handle:
            entry = next(EntrySet(handle))
            return KeyEntry(
                entry.category, entry.name, json.loads(entry.value), entry.tags
            )

    async def sign_message(self, key_ident: str, message: [str, bytes]) -> bytes:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot sign message with closed store"
            )
        buf = await bindings.store_sign_message(self.handle, key_ident, message)
        return bytes(buf)

    async def verify_signature(
        self, signer_vk: str, message: [str, bytes], signature: [str, bytes]
    ) -> bool:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot verify signature with closed store"
            )
        return await bindings.store_verify_signature(
            self.handle, signer_vk, message, signature
        )

    async def pack_message(
        self,
        recipient_vks: Sequence[str],
        from_key_ident: Optional[str],
        message: [str, bytes],
    ) -> str:
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot pack message with closed store"
            )
        return bytes(
            await bindings.store_pack_message(
                self.handle, recipient_vks, from_key_ident, message
            )
        ).decode("utf-8")

    async def unpack_message(
        self,
        message: [str, bytes],
    ) -> (bytes, str, Optional[str]):
        if not self.handle:
            raise StoreError(
                StoreErrorCode.WRAPPER, "Cannot unpack message with closed store"
            )
        return await bindings.store_unpack_message(self.handle, message)


async def _wrap_open_store(fut: asyncio.Future) -> Store:
    return Store(await fut)


class StoreOpen:
    def __init__(self, fut: asyncio.Future):
        self._fut = _wrap_open_store(fut)
        self._store: Store = None

    def __await__(self) -> Store:
        if not self._fut:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot reuse store opening")
        fut = self._fut
        self._fut = None
        return fut.__await__()

    async def __aenter__(self) -> Store:
        if not self._fut:
            raise StoreError(StoreErrorCode.WRAPPER, "Cannot reuse store opening")
        self._store = await self._fut
        self._fut = None
        return self._store

    async def __aexit__(self, exc_type, exc, tb):
        await self._store.close()
