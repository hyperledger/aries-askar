"""Error classes."""

from enum import IntEnum


class StoreErrorCode(IntEnum):
    SUCCESS = 0
    BACKEND = 1
    BUSY = 2
    DISCONNECTED = 3
    ENCRYPTION = 4
    INPUT = 5
    LOCK = 6
    TIMEOUT = 7
    UNEXPECTED = 8
    UNSUPPORTED = 9
    WRAPPER = 99


class StoreError(Exception):
    def __init__(self, code: StoreErrorCode, message: str, extra: str = None):
        super().__init__(message)
        self.code = code
        self.extra = extra
