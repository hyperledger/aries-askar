"""Handling of Store instances."""

import json

from typing import Optional, Sequence, Union

from cached_property import cached_property

from . import bindings

from .bindings import (
    EntryListHandle,
    KeyEntryListHandle,
    ScanHandle,
    SessionHandle,
    StoreHandle,
)
from .error import AskarError, AskarErrorCode
from .key import Key
from .types import EntryOperation, KeyAlg


class Entry:
    """A single result from a store query."""

    _KEYS = ("name", "category", "value", "tags")

    def __init__(self, lst: EntryListHandle, pos: int):
        """Initialize the EntryHandle."""
        self._list = lst
        self._pos = pos

    @cached_property
    def category(self) -> str:
        """Accessor for the entry category."""
        return self._list.get_category(self._pos)

    @cached_property
    def name(self) -> str:
        """Accessor for the entry name."""
        return self._list.get_name(self._pos)

    @property
    def value(self) -> bytes:
        """Accessor for the entry value."""
        return bytes(self.raw_value)

    @cached_property
    def raw_value(self) -> memoryview:
        """Accessor for the entry raw value."""
        return self._list.get_value(self._pos)

    @property
    def value_json(self) -> dict:
        """Accessor for the entry value as JSON."""
        return json.loads(self.value)

    @cached_property
    def tags(self) -> dict:
        """Accessor for the entry tags."""
        return self._list.get_tags(self._pos)

    def keys(self):
        """Mapping keys."""
        return Entry._KEYS

    def __getitem__(self, key):
        """Accessor for mapping value."""
        if key in Entry._KEYS:
            return getattr(self, key)
        return KeyError

    def __repr__(self) -> str:
        """Format entry handle as a string."""
        return (
            f"<Entry(category={repr(self.category)}, name={repr(self.name)}, "
            f"value={self.value}, tags={self.tags})>"
        )


class EntryList:
    """A list of query results."""

    def __init__(self, handle: EntryListHandle, len: int = None):
        """Initialize the EntryList instance."""
        self._handle = handle
        self._pos = 0
        if handle:
            self._len = bindings.entry_list_count(self._handle) if len is None else len
        else:
            self._len = 0

    @property
    def handle(self) -> EntryListHandle:
        """Accessor for the entry list handle."""
        return self._handle

    def __getitem__(self, index) -> Entry:
        if not isinstance(index, int) or index < 0 or index >= self._len:
            return IndexError()
        return Entry(self._handle, index)

    def __iter__(self):
        return self

    def __next__(self):
        if self._pos < self._len:
            entry = Entry(self._handle, self._pos)
            self._pos += 1
            return entry
        else:
            raise StopIteration

    def __len__(self) -> int:
        return self._len

    def __repr__(self) -> str:
        return f"<EntryList(handle={self._handle}, pos={self._pos}, len={self._len})>"


class KeyEntry:
    """Pointer to one result of a KeyEntryList instance."""

    def __init__(self, lst: KeyEntryListHandle, pos: int):
        """Initialize the KeyEntryHandle."""
        self._list = lst
        self._pos = pos

    @cached_property
    def algorithm(self) -> str:
        """Accessor for the key entry algorithm."""
        return self._list.get_algorithm(self._pos)

    @cached_property
    def name(self) -> str:
        """Accessor for the key entry name."""
        return self._list.get_name(self._pos)

    @cached_property
    def metadata(self) -> str:
        """Accessor for the key entry metadata."""
        return self._list.get_metadata(self._pos)

    @cached_property
    def key(self) -> Key:
        """Accessor for the entry metadata."""
        return Key(self._list.load_key(self._pos))

    @cached_property
    def tags(self) -> dict:
        """Accessor for the entry tags."""
        return self._list.get_tags(self._pos)

    def __repr__(self) -> str:
        """Format key entry handle as a string."""
        return (
            f"<KeyEntry(algorithm={repr(self.algorithm)}, name={repr(self.name)}, "
            f"metadata={repr(self.metadata)}, key={self.key}, tags={self.tags})>"
        )


class KeyEntryList:
    """A list of key query results."""

    def __init__(self, handle: KeyEntryListHandle, len: int = None):
        """Initialize the KeyEntryList instance."""
        self._handle = handle
        self._pos = 0
        if handle:
            self._len = (
                bindings.key_entry_list_count(self._handle) if len is None else len
            )
        else:
            self._len = 0

    @property
    def handle(self) -> KeyEntryListHandle:
        """Accessor for the key entry list handle."""
        return self._handle

    def __getitem__(self, index) -> KeyEntry:
        if not isinstance(index, int) or index < 0 or index >= self._len:
            return IndexError()
        return KeyEntry(self._handle, index)

    def __iter__(self):
        return self

    def __next__(self):
        if self._pos < self._len:
            entry = KeyEntry(self._handle, self._pos)
            self._pos += 1
            return entry
        else:
            raise StopIteration

    def __len__(self) -> int:
        return self._len

    def __repr__(self) -> str:
        return (
            f"<KeyEntryList(handle={self._handle}, pos={self._pos}, len={self._len})>"
        )


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
        self._handle: ScanHandle = None
        self._buffer: EntryList = None

    @property
    def handle(self) -> ScanHandle:
        """Accessor for the scan handle."""
        return self._handle

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._handle is None:
            (store, profile, category, tag_filter, offset, limit) = self.params
            if not store.handle:
                raise AskarError(
                    AskarErrorCode.WRAPPER, "Cannot scan from closed store"
                )
            self._handle = await bindings.scan_start(
                store.handle, profile, category, tag_filter, offset, limit
            )
            list_handle = await bindings.scan_next(self._handle)
            self._buffer = EntryList(list_handle) if list_handle else None
        while True:
            if not self._buffer:
                raise StopAsyncIteration
            row = next(self._buffer, None)
            if row:
                return row
            list_handle = await bindings.scan_next(self._handle)
            self._buffer = EntryList(list_handle) if list_handle else None

    async def fetch_all(self) -> Sequence[Entry]:
        rows = []
        async for row in self:
            rows.append(row)
        return rows

    def __repr__(self) -> str:
        return f"<Scan(handle={self._handle})>"


class Store:
    """An opened Store instance."""

    def __init__(self, handle: StoreHandle, uri: str):
        """Initialize the Store instance."""
        self._handle = handle
        self._opener: OpenSession = None
        self._uri = uri

    @classmethod
    def generate_raw_key(cls, seed: Union[str, bytes] = None) -> str:
        """Generate a new raw key for a Store."""
        return bindings.generate_raw_key(seed)

    @property
    def handle(self) -> StoreHandle:
        """Accessor for the store handle."""
        return self._handle

    @property
    def uri(self) -> str:
        """Accessor for the store URI."""
        return self._uri

    @classmethod
    async def provision(
        cls,
        uri: str,
        key_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
        recreate: bool = False,
    ) -> "Store":
        return Store(
            await bindings.store_provision(
                uri, key_method, pass_key, profile, recreate
            ),
            uri,
        )

    @classmethod
    async def open(
        cls,
        uri: str,
        key_method: str = None,
        pass_key: str = None,
        *,
        profile: str = None,
    ) -> "Store":
        return Store(await bindings.store_open(uri, key_method, pass_key, profile), uri)

    @classmethod
    async def remove(cls, uri: str) -> bool:
        return await bindings.store_remove(uri)

    async def __aenter__(self) -> "Session":
        if not self._opener:
            self._opener = OpenSession(self, None, False)
        return await self._opener.__aenter__()

    async def __aexit__(self, exc_type, exc, tb):
        return await self._opener.__aexit__(exc_type, exc, tb)

    async def create_profile(self, name: str = None) -> str:
        return await bindings.store_create_profile(self._handle, name)

    async def get_profile_name(self) -> str:
        return await bindings.store_get_profile_name(self._handle)

    async def remove_profile(self, name: str) -> bool:
        return await bindings.store_remove_profile(self._handle, name)

    async def rekey(
        self,
        key_method: str = None,
        pass_key: str = None,
    ):
        await bindings.store_rekey(self._handle, key_method, pass_key)

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

    async def close(self, *, remove: bool = False) -> bool:
        """Close and free the pool instance."""
        self._opener = None
        if self._handle:
            await self._handle.close()
            self._handle = None
        if remove:
            return await Store.remove(self._uri)
        else:
            return False

    def __repr__(self) -> str:
        return f"<Store(handle={self._handle})>"


class Session:
    """An opened Session instance."""

    def __init__(self, store: Store, handle: SessionHandle, is_txn: bool):
        """Initialize the Session instance."""
        self._store = store
        self._handle = handle
        self._is_txn = is_txn

    @property
    def is_transaction(self) -> bool:
        """Determine if the session is a transaction."""
        return self._is_txn

    @property
    def handle(self) -> SessionHandle:
        """Accessor for the SessionHandle instance."""
        return self._handle

    @property
    def store(self) -> Store:
        """Accessor for the Store instance."""
        return self._store

    async def count(self, category: str, tag_filter: Union[str, dict] = None) -> int:
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot count from closed session")
        return await bindings.session_count(self._handle, category, tag_filter)

    async def fetch(
        self, category: str, name: str, *, for_update: bool = False
    ) -> Optional[Entry]:
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot fetch from closed session")
        result_handle = await bindings.session_fetch(
            self._handle, category, name, for_update
        )
        return next(EntryList(result_handle, 1), None) if result_handle else None

    async def fetch_all(
        self,
        category: str,
        tag_filter: Union[str, dict] = None,
        limit: int = None,
        *,
        for_update: bool = False,
    ) -> EntryList:
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot fetch from closed session")
        return EntryList(
            await bindings.session_fetch_all(
                self._handle, category, tag_filter, limit, for_update
            )
        )

    async def insert(
        self,
        category: str,
        name: str,
        value: Union[str, bytes] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self._handle, EntryOperation.INSERT, category, name, value, tags, expiry_ms
        )

    async def replace(
        self,
        category: str,
        name: str,
        value: Union[str, bytes] = None,
        tags: dict = None,
        expiry_ms: int = None,
        value_json=None,
    ):
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        if value is None and value_json is not None:
            value = json.dumps(value_json)
        await bindings.session_update(
            self._handle, EntryOperation.REPLACE, category, name, value, tags, expiry_ms
        )

    async def remove(
        self,
        category: str,
        name: str,
    ):
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot update closed session")
        await bindings.session_update(
            self._handle, EntryOperation.REMOVE, category, name
        )

    async def remove_all(
        self,
        category: str,
        tag_filter: Union[str, dict] = None,
    ) -> int:
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot remove all for closed session"
            )
        return await bindings.session_remove_all(self._handle, category, tag_filter)

    async def insert_key(
        self,
        name: str,
        key: Key,
        *,
        metadata: str = None,
        tags: dict = None,
        expiry_ms: int = None,
    ) -> str:
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot insert key with closed session"
            )
        return str(
            await bindings.session_insert_key(
                self._handle, key._handle, name, metadata, tags, expiry_ms
            )
        )

    async def fetch_key(
        self, name: str, *, for_update: bool = False
    ) -> Optional[KeyEntry]:
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot fetch key from closed session"
            )
        result_handle = await bindings.session_fetch_key(self._handle, name, for_update)
        return next(KeyEntryList(result_handle, 1)) if result_handle else None

    async def fetch_all_keys(
        self,
        *,
        alg: Union[str, KeyAlg] = None,
        thumbprint: str = None,
        tag_filter: Union[str, dict] = None,
        limit: int = None,
        for_update: bool = False,
    ) -> KeyEntryList:
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot fetch key from closed session"
            )
        result_handle = await bindings.session_fetch_all_keys(
            self._handle, alg, thumbprint, tag_filter, limit, for_update
        )
        return KeyEntryList(result_handle)

    async def update_key(
        self,
        name: str,
        *,
        metadata: str = None,
        tags: dict = None,
        expiry_ms: int = None,
    ):
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot update key with closed session"
            )
        await bindings.session_update_key(self._handle, name, metadata, tags, expiry_ms)

    async def remove_key(self, name: str):
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot remove key with closed session"
            )
        await bindings.session_remove_key(self._handle, name)

    async def commit(self):
        if not self._is_txn:
            raise AskarError(AskarErrorCode.WRAPPER, "Session is not a transaction")
        if not self._handle:
            raise AskarError(AskarErrorCode.WRAPPER, "Cannot commit closed transaction")
        await self._handle.close(commit=True)
        self._handle = None

    async def rollback(self):
        if not self._is_txn:
            raise AskarError(AskarErrorCode.WRAPPER, "Session is not a transaction")
        if not self._handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot rollback closed transaction"
            )
        await self._handle.close(commit=False)
        self._handle = None

    async def close(self):
        if self._handle:
            await self.handle.close(commit=False)
            self._handle = None

    def __repr__(self) -> str:
        return f"<Session(handle={self._handle}, is_transaction={self._is_txn})>"


class OpenSession:
    def __init__(self, store: Store, profile: Optional[str], is_txn: bool):
        """Initialize the OpenSession instance."""
        self._store = store
        self._profile = profile
        self._is_txn = is_txn
        self._session = None

    @property
    def is_transaction(self) -> bool:
        return self._is_txn

    async def _open(self) -> Session:
        if not self._store.handle:
            raise AskarError(
                AskarErrorCode.WRAPPER, "Cannot start session from closed store"
            )
        if self._session:
            raise AskarError(AskarErrorCode.WRAPPER, "Session already opened")
        self._session = Session(
            self._store,
            await bindings.session_start(
                self._store.handle, self._profile, self._is_txn
            ),
            self._is_txn,
        )
        return self._session

    def __await__(self) -> Session:
        return self._open().__await__()

    async def __aenter__(self) -> Session:
        return await self._open()

    async def __aexit__(self, exc_type, exc, tb):
        await self._session.close()
        self._session = None
