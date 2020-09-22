"""Low-level interaction with the aries-askar library."""

import asyncio
import json
import logging
import os
import sys
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    byref,
    cast,
    pointer,
    sizeof,
    c_char_p,
    c_long,
    c_size_t,
    c_void_p,
    c_ubyte,
    c_ulong,
    Structure,
)
from ctypes.util import find_library
from typing import Optional, Union, Sequence

from .error import StoreError, StoreErrorCode
from .types import Entry, UpdateEntry


CALLBACKS = {}
LIB: CDLL = None
LOGGER = logging.getLogger(__name__)


class StoreHandle(c_size_t):
    """Index of an active Store instance."""

    def __repr__(self) -> str:
        """Format store handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class ScanHandle(c_size_t):
    """Index of an active Store scan instance."""

    def __repr__(self) -> str:
        """Format scan handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class LockHandle(c_size_t):
    """Index of an active Lock instance."""

    def __repr__(self) -> str:
        """Format lock handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class EntrySetHandle(c_size_t):
    """Index of an active EntrySet instance."""

    def __repr__(self) -> str:
        """Format entry set handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class FfiTag(Structure):
    _fields_ = [
        ("name", c_char_p),
        ("value", c_char_p),
    ]


class FfiEntry(Structure):
    _fields_ = [
        ("category", c_char_p),
        ("name", c_char_p),
        ("value", c_void_p),
        ("value_len", c_size_t),
        ("tags", POINTER(FfiTag)),
        ("tags_len", c_size_t),
    ]

    def decode(self) -> Entry:
        value = bytes((c_ubyte * self.value_len).from_address(self.value))
        if self.tags_len % sizeof(FfiTag) != 0:
            raise StoreError(StoreErrorCode.WRAPPER, "Invalid length for tags")
        tag_count = self.tags_len // sizeof(FfiTag)
        if tag_count:
            tags_lst = cast(self.tags, POINTER(FfiTag * tag_count)).contents
            tags = {}
            for tag in tags_lst:
                tags[decode_str(tag.name)] = decode_str(tag.value)
        else:
            tags = None
        return Entry(
            decode_str(self.category),
            decode_str(self.name),
            value,
            tags,
        )


class FfiUpdateEntry(Structure):
    _fields_ = [
        ("entry", FfiEntry),
        ("expire_ms", c_ulong),
    ]

    @classmethod
    def encode(cls, upd: UpdateEntry) -> "FfiUpdateEntry":
        if upd.tags:
            tags = (FfiTag * len(upd.tags))()
            tag_idx = 0
            for tag_name, tag_value in upd.tags.items():
                tags[tag_idx] = FfiTag(
                    encode_str(tag_name),
                    encode_str(tag_value),
                )
                tag_idx += 1
            tags_len = sizeof(tags)
        else:
            tags = None
            tags_len = 0
        category = encode_str(upd.category)
        name = encode_str(upd.name)
        entry = FfiEntry(
            category,
            name,
            cast(upd.value, c_void_p),
            len(upd.value),
            tags,
            tags_len,
        )
        return FfiUpdateEntry(
            entry,
            -1 if upd.expire_ms is None else upd.expire_ms,
        )


class lib_string(c_char_p):
    """A string allocated by the library."""

    @classmethod
    def from_param(cls):
        """Returns the type ctypes should use for loading the result."""
        return c_void_p

    def __bytes__(self):
        """Convert to bytes."""
        return self.value

    def __str__(self):
        """Convert to str."""
        return self.value.decode("utf-8")

    def __del__(self):
        """Call the string destructor when this instance is released."""
        get_library().askar_string_free(self)


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("aries_askar")
        do_call("askar_set_default_logger")
    return LIB


def _load_library(lib_name: str) -> CDLL:
    """Load the CDLL library.
    The python module directory is searched first, followed by the usual
    library resolution for the current system.
    """
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        LOGGER.debug("Unknown platform for shared library")
    except OSError:
        LOGGER.warning("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        raise StoreError(StoreErrorCode.WRAPPER, f"Error loading library: {lib_name}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise StoreError(
            StoreErrorCode.WRAPPER, f"Error loading library: {lib_name}"
        ) from e


def _fulfill_future(fut: asyncio.Future, result, err: Exception = None):
    """Resolve a callback future given the result and exception, if any."""
    if fut.cancelled():
        LOGGER.debug("callback previously cancelled")
    elif err:
        fut.set_exception(err)
    else:
        fut.set_result(result)


def _create_callback(cb_type: CFUNCTYPE, fut: asyncio.Future, post_process=None):
    """Create a callback to handle the response from an async library method."""

    def _cb(id: int, err: int, result=None):
        """Callback function passed to the CFUNCTYPE for invocation."""
        if post_process:
            result = post_process(result)
        exc = get_current_error() if err else None
        try:
            (loop, _cb) = CALLBACKS.pop(fut)
        except KeyError:
            LOGGER.debug("callback already fulfilled")
            return
        loop.call_soon_threadsafe(lambda: _fulfill_future(fut, result, exc))

    res = cb_type(_cb)
    return res


def do_call(fn_name, *args):
    """Perform a synchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    result = lib_fn(*args)
    if result:
        raise get_current_error(True)


def do_call_async(
    fn_name, *args, return_type=None, post_process=None
) -> asyncio.Future:
    """Perform an asynchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    cf_args = [None, c_size_t, c_size_t]
    if return_type:
        cf_args.append(return_type)
    cb_type = CFUNCTYPE(*cf_args)  # could be cached
    cb_res = _create_callback(cb_type, fut, post_process)
    # keep a reference to the callback function to avoid it being freed
    CALLBACKS[fut] = (loop, cb_res)
    result = lib_fn(*args, cb_res, c_size_t(0))  # not making use of callback ID
    if result:
        # callback will not be executed
        if CALLBACKS.pop(fut):
            fut.set_exception(get_current_error())
    return fut


def decode_str(value: c_char_p) -> str:
    return value.decode("utf-8")


def encode_str(arg: Optional[Union[str, bytes]]) -> c_char_p:
    """Encode an optional input argument as a string.
    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return None
    if isinstance(arg, bytes):
        return c_char_p(arg)
    return c_char_p(arg.encode("utf-8"))


def get_current_error(expect: bool = False) -> StoreError:
    """Get the error result from the previous failed API method.
    Args:
        expect: Return a default error message if none is found
    """
    err_json = lib_string()
    if not get_library().askar_get_current_error(byref(err_json)):
        try:
            msg = json.loads(err_json.value)
        except json.JSONDecodeError:
            LOGGER.warning("JSON decode error for askar_get_current_error")
            msg = None
        if msg and "message" in msg and "code" in msg:
            return StoreError(
                StoreErrorCode(msg["code"]), msg["message"], msg.get("extra")
            )
        if not expect:
            return None
    return StoreError(StoreErrorCode.WRAPPER, "Unknown error")


def generate_raw_key() -> str:
    """Generate a new raw store wrapping key."""
    result = lib_string()
    do_call("askar_store_generate_raw_key", byref(result))
    return result.value.decode("utf-8")


async def store_provision(
    uri: str, wrap_method: str = None, pass_key: str = None
) -> StoreHandle:
    """Provision a new Store and return the open handle."""
    uri_p = encode_str(uri)
    wrap_method_p = encode_str(wrap_method)
    pass_key_p = encode_str(pass_key)
    return await do_call_async(
        "askar_store_provision",
        uri_p,
        wrap_method_p,
        pass_key_p,
        return_type=StoreHandle,
    )


async def store_open(uri: str, pass_key: str = None) -> StoreHandle:
    """Open an existing Store and return the open handle."""
    uri_p = encode_str(uri)
    pass_key_p = encode_str(pass_key)
    return await do_call_async(
        "askar_store_open",
        uri_p,
        pass_key_p,
        return_type=StoreHandle,
    )


async def store_count(
    handle: StoreHandle, category: [str, bytes], tag_filter: [str, dict] = None
) -> int:
    """Count rows in the Store."""
    category = encode_str(category)
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    tag_filter = encode_str(tag_filter)
    return int(
        await do_call_async(
            "askar_store_count", handle, category, tag_filter, return_type=c_size_t
        )
    )


async def store_fetch(
    handle: StoreHandle, category: [str, bytes], name: [str, bytes]
) -> EntrySetHandle:
    """Fetch a row from the Store."""
    category = encode_str(category)
    name = encode_str(name)
    return await do_call_async(
        "askar_store_fetch", handle, category, name, return_type=EntrySetHandle
    )


async def store_scan_start(
    handle: StoreHandle, category: [str, bytes], tag_filter: [str, dict] = None
) -> ScanHandle:
    """Fetch a row from the Store."""
    category = encode_str(category)
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    tag_filter = encode_str(tag_filter)
    return await do_call_async(
        "askar_store_scan_start", handle, category, tag_filter, return_type=ScanHandle
    )


async def store_scan_next(handle: StoreHandle) -> Optional[EntrySetHandle]:
    handle = await do_call_async(
        "askar_store_scan_next", handle, return_type=EntrySetHandle
    )
    return handle or None


def store_scan_free(handle: ScanHandle):
    """Free an active store scan."""
    do_call("askar_store_scan_free", handle)


def store_results_next(handle: EntrySetHandle) -> Optional[Entry]:
    ffi_entry = FfiEntry()
    found = c_ubyte(0)
    do_call("askar_store_results_next", handle, byref(ffi_entry), byref(found))
    if found:
        return ffi_entry.decode()
    return None


def store_results_free(handle: EntrySetHandle):
    get_library().askar_store_results_free(handle)


async def store_update(handle: StoreHandle, entries: Sequence[UpdateEntry]):
    """Update a Store by inserting, updating, and removing records."""

    updates = (FfiUpdateEntry * len(entries))()
    for idx, upd in enumerate(entries):
        updates[idx] = FfiUpdateEntry.encode(upd)

    return await do_call_async(
        "askar_store_update",
        handle,
        updates,
        sizeof(updates),
    )


async def store_create_lock(
    handle: StoreHandle, lock_info: UpdateEntry, acquire_timeout_ms: int = None
) -> LockHandle:
    ffi_info = FfiUpdateEntry.encode(lock_info)
    timeout = c_long(acquire_timeout_ms if acquire_timeout_ms is not None else -1)
    return await do_call_async(
        "askar_store_create_lock",
        handle,
        pointer(ffi_info),
        timeout,
        return_type=LockHandle,
    )


def store_lock_get_entry(handle: LockHandle) -> Entry:
    ffi_entry = FfiEntry()
    do_call("askar_store_lock_get_entry", handle, byref(ffi_entry))
    return ffi_entry.decode()


def store_lock_free(handle: LockHandle):
    get_library().askar_store_lock_free(handle)


async def store_lock_update(handle: LockHandle, entries: Sequence[UpdateEntry]):
    updates = (FfiUpdateEntry * len(entries))()
    for idx, upd in enumerate(entries):
        updates[idx] = FfiUpdateEntry.encode(upd)

    return await do_call_async(
        "askar_store_lock_update",
        handle,
        updates,
        sizeof(updates),
    )


async def store_close(handle: StoreHandle):
    """Close an opened store instance."""
    return await do_call_async("askar_store_close", handle)


def store_close_immed(handle: StoreHandle):
    """Close an opened store instance."""
    do_call("askar_store_close", handle, c_void_p(0), c_size_t(0))


def version() -> str:
    """Set the version of the installed aries-askar library."""
    lib = get_library()
    lib.askar_version.restype = c_void_p
    return lib_string(lib.askar_version()).value.decode("utf-8")
