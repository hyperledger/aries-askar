"""Error classes."""

from enum import IntEnum


class StoreErrorCode(IntEnum):
    SUCCESS = 0
    BACKEND = 1
    BUSY = 2
    DISCONNECTED = 3
    DUPLICATE = 4
    ENCRYPTION = 5
    INPUT = 6
    LOCK = 7
    TIMEOUT = 8
    UNEXPECTED = 9
    UNSUPPORTED = 10
    WRAPPER = 99


class StoreError(Exception):
    def __init__(self, code: StoreErrorCode, message: str, extra: str = None):
        super().__init__(message)
        self.code = code
        self.extra = extra
