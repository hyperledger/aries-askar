import json as _json

from enum import Enum
from typing import Mapping, Optional


def _make_bytes(value: [str, bytes]) -> bytes:
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
        self.value = _make_bytes(value)
        self.tags = dict(tags) if tags else {}

    @property
    def json(self):
        None if self.value is None else _json.loads(self.value)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(category={repr(self.category)}, "
            f"name={repr(self.name)}, value={repr(self.value)}, tags={self.tags})"
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


class UpdateEntry:
    def __init__(
        self,
        category: str,
        name: str,
        value: [str, bytes] = None,
        tags: Mapping[str, str] = None,
        expire_ms: Optional[int] = None,
        profile_id: Optional[int] = None,
        json=None,
    ) -> "Entry":
        self.category = category
        self.name = name
        if value is not None:
            self.value = _make_bytes(value)
        elif json is not None:
            self.value = _make_bytes(_json.dumps(json))
        else:
            self.value = None
        self.tags = dict(tags) if tags else {}
        self.expire_ms = expire_ms
        self.profile_id = profile_id

    @property
    def json(self):
        None if self.value is None else _json.loads(self.value)

    @json.setter
    def json(self, val):
        self.value = None if val is None else _make_bytes(_json.dumps(val))


class KeyAlg(Enum):
    ED25519 = "ed25519"
