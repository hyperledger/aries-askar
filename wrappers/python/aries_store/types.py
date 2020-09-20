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

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}(category={repr(self.category)}, "
            f"name={repr(self.name)}, value={repr(self.value)}, tags={self.tags})"
        )


class UpdateEntry:
    def __init__(
        self,
        category: str,
        name: str,
        value: [str, bytes],
        tags: Mapping[str, str] = None,
        expire_ms: Optional[int] = None,
        profile_id: Optional[int] = None,
    ) -> "Entry":
        self.category = category
        self.name = name
        self.value = _make_bytes(value)
        self.tags = dict(tags) if tags else {}
        self.expire_ms = expire_ms
        self.profile_id = profile_id
