import json as _json

from enum import Enum
from typing import Mapping


def _make_binary(value: [str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    else:
        return value


class Entry:
    def __init__(
        self,
        category: str,
        name: str,
        value: [str, bytes],
        tags: Mapping[str, str] = None,
    ) -> "Entry":
        self.category = category
        self.name = name
        self._value = _make_binary(value)
        self.tags = dict(tags) if tags else {}
        self.entry_set = None

    @property
    def raw_value(self) -> memoryview:
        val = self._value
        if val is None:
            return None
        if isinstance(val, memoryview):
            return val
        return memoryview(val)

    @property
    def value(self) -> bytes:
        val = self._value
        if val is None:
            return None
        if isinstance(val, memoryview):
            return bytes(val)
        return val

    @property
    def value_json(self):
        val = self.value
        return None if val is None else _json.loads(val)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(category={repr(self.category)}, "
            f"name={repr(self.name)}, value={repr(self.value)}, "
            f"tags={self.tags})"
        )


class KeyEntry:
    def __init__(
        self,
        category: str,
        ident: str,
        params: dict,
        tags: Mapping[str, str] = None,
    ) -> "Entry":
        self.category = category
        self.ident = ident
        self.params = params
        self.tags = dict(tags) if tags else {}

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(category={repr(self.category)}, "
            f"ident={repr(self.ident)}, params=.., tags={self.tags})"
        )


class KeyAlg(Enum):
    ED25519 = "ed25519"


class EntryOperation(Enum):
    INSERT = 0
    REPLACE = 1
    REMOVE = 2
