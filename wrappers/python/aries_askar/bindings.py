"""Low-level interaction with the aries-askar library."""

import asyncio
import json
import logging
import os
import sys
from ctypes import (
    _SimpleCData,
    Array,
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
    cast,
    c_char_p,
    c_int8,
    c_int32,
    c_int64,
    c_size_t,
    c_void_p,
    c_ubyte,
)
from ctypes.util import find_library
from typing import Optional, Tuple, Union

from .error import AskarError, AskarErrorCode
from .types import EntryOperation, KeyAlg, SeedMethod


CALLBACKS = {}
INVOKE = {}
LIB: CDLL = None
LOGGER = logging.getLogger(__name__)
LOG_LEVELS = {
    1: logging.ERROR,
    2: logging.WARNING,
    3: logging.INFO,
    4: logging.DEBUG,
}
MODULE_NAME = __name__.split(".")[0]


class RawBuffer(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("len", c_int64),
        ("data", POINTER(c_ubyte)),
    ]

    def __bytes__(self) -> bytes:
        if not self.len:
            return b""
        return bytes(self.array)

    def __len__(self) -> int:
        return int(self.len)

    @property
    def array(self) -> Array:
        return cast(self.data, POINTER(c_ubyte * self.len)).contents


class FfiByteBuffer:
    """A byte buffer allocated by Python."""

    def __init__(self, value):
        if isinstance(value, str):
            value = value.encode("utf-8")

        if value is None:
            dlen = 0
            data = c_char_p()
        elif isinstance(value, memoryview):
            dlen = value.nbytes
            data = c_char_p(value.tobytes())
        elif isinstance(value, bytes):
            dlen = len(value)
            data = c_char_p(value)
            b = c_void_p.from_buffer(data)
            del b
        else:
            raise TypeError(f"Expected str or bytes value, got {type(value)}")
        self._dlen = dlen
        self._data = data

    def __bytes__(self) -> bytes:
        if not self._data:
            return b""
        return self._data.value

    def __len__(self) -> int:
        return self._dlen

    @property
    def _as_parameter_(self) -> RawBuffer:
        buf = RawBuffer(len=self._dlen, data=cast(self._data, POINTER(c_ubyte)))
        return buf

    @classmethod
    def from_param(cls, value):
        if isinstance(value, (ByteBuffer, FfiByteBuffer)):
            return value
        return cls(value)


class ByteBuffer(Structure):
    """A managed byte buffer allocated by the library."""

    _fields_ = [("buffer", RawBuffer)]

    @property
    def array(self) -> Array:
        return self.buffer.array

    @property
    def view(self) -> memoryview:
        return memoryview(self.array)

    def __bytes__(self) -> bytes:
        return bytes(self.buffer)

    def __len__(self) -> int:
        return len(self.buffer)

    def __getitem__(self, idx) -> bytes:
        return bytes(self.buffer.array[idx])

    def __repr__(self) -> str:
        """Format byte buffer as a string."""
        return f"{self.__class__.__name__}({bytes(self)})"

    def __del__(self):
        """Call the byte buffer destructor when this instance is released."""
        invoke_dtor("askar_buffer_free", self.buffer)


class FfiStr:
    def __init__(self, value=None):
        if value is None:
            value = c_char_p()
        elif isinstance(value, c_char_p):
            pass
        else:
            if isinstance(value, str):
                value = value.encode("utf-8")
            if not isinstance(value, bytes):
                raise TypeError(f"Expected string value, got {type(value)}")
            value = c_char_p(value)
        self.value = value

    @classmethod
    def from_param(cls, value):
        if isinstance(value, cls):
            return value
        return cls(value)

    @property
    def _as_parameter_(self):
        return self.value

    def __repr__(self) -> str:
        """Format handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class FfiJson:
    @classmethod
    def from_param(cls, value):
        if isinstance(value, FfiStr):
            return value
        if isinstance(value, dict):
            value = json.dumps(value)
        return FfiStr(value)


class FfiTagsJson:
    @classmethod
    def from_param(cls, tags):
        if isinstance(tags, FfiStr):
            return tags
        if tags:
            tags = json.dumps(
                {
                    name: (list(value) if isinstance(value, set) else value)
                    for name, value in tags.items()
                }
            )
        else:
            tags = None
        return FfiStr(tags)


class StrBuffer(c_char_p):
    """A string allocated by the library."""

    def is_none(self) -> bool:
        """Check if the returned string pointer is null."""
        return self.value is None

    def opt_str(self) -> Optional[str]:
        """Convert to an optional string."""
        val = self.value
        return val.decode("utf-8") if val is not None else None

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        return self.value

    def __str__(self):
        """Convert to a string."""
        # not allowed to return None
        val = self.opt_str()
        return val if val is not None else ""

    def __del__(self):
        """Call the string destructor when this instance is released."""
        if self:
            invoke_dtor("askar_string_free", self)


class AeadParams(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("nonce_length", c_int32),
        ("tag_length", c_int32),
    ]

    def __repr__(self) -> str:
        """Format AEAD params as a string."""
        return (
            f"<AeadParams(nonce_length={self.nonce_length}, "
            f"tag_length={self.tag_length})>"
        )


class Encrypted(Structure):
    """The result of an AEAD encryption operation."""

    _fields_ = [
        ("buffer", RawBuffer),
        ("tag_pos", c_int64),
        ("nonce_pos", c_int64),
    ]

    def __getitem__(self, idx) -> bytes:
        return bytes(self.buffer.array[idx])

    def __bytes__(self) -> bytes:
        """Convert to bytes."""
        return self.ciphertext_tag

    @property
    def ciphertext_tag(self) -> bytes:
        """Accessor for the combined ciphertext and tag."""
        p = self.nonce_pos
        return self[:p]

    @property
    def ciphertext(self) -> bytes:
        """Accessor for the ciphertext."""
        p = self.tag_pos
        return self[:p]

    @property
    def nonce(self) -> bytes:
        """Accessor for the nonce."""
        p = self.nonce_pos
        return self[p:]

    @property
    def tag(self) -> bytes:
        """Accessor for the authentication tag."""
        p1 = self.tag_pos
        p2 = self.nonce_pos
        return self[p1:p2]

    @property
    def parts(self) -> Tuple[bytes, bytes, bytes]:
        """Accessor for the ciphertext, tag, and nonce."""
        p1 = self.tag_pos
        p2 = self.nonce_pos
        return self[:p1], self[p1:p2], self[p2:]

    def __repr__(self) -> str:
        """Format encrypted value as a string."""
        return (
            f"<Encrypted(ciphertext={self.ciphertext}, tag={self.tag},"
            f" nonce={self.nonce})>"
        )

    def __del__(self):
        """Call the byte buffer destructor when this instance is released."""
        invoke_dtor("askar_buffer_free", self.buffer)


class ArcHandle(Structure):
    """Base class for handle instances."""

    _fields_ = [
        ("value", c_size_t),
    ]

    def __init__(self, value=0):
        if isinstance(value, c_size_t):
            value = value.value
        if not isinstance(value, int):
            raise ValueError("Invalid handle")
        super().__init__(value)

    @classmethod
    def from_param(cls, param):
        if isinstance(param, cls):
            return param
        return cls(param)

    def __bool__(self):
        return bool(self.value)

    def __repr__(self) -> str:
        """Format handle as a string."""
        return f"{self.__class__.__name__}({self.value})"


class StoreHandle(ArcHandle):
    """Handle for an active Store instance."""

    async def close(self):
        """Close the store, waiting for any active connections."""
        if self:
            await invoke_async("askar_store_close", (StoreHandle,), self)
            self.value = 0

    def __del__(self):
        """Close the store when there are no more references to this object."""
        if self:
            invoke_dtor(
                "askar_store_close",
                self,
                None,
                0,
                argtypes=(StoreHandle, c_void_p, c_int64),
            )


class SessionHandle(ArcHandle):
    """Handle for an active Session/Transaction instance."""

    async def close(self, commit: bool = False):
        """Close the session."""
        if self:
            await invoke_async(
                "askar_session_close",
                (SessionHandle, c_int8),
                self,
                commit,
            )
            self.value = 0

    def __del__(self):
        """Close the session when there are no more references to this object."""
        if self:
            invoke_dtor(
                "askar_session_close",
                self,
                0,
                None,
                0,
                argtypes=(SessionHandle, c_int8, c_void_p, c_int64),
            )


class ScanHandle(ArcHandle):
    """Handle for an active Store scan instance."""

    def __del__(self):
        """Close the scan when there are no more references to this object."""
        invoke_dtor("askar_scan_free", self)


class EntryListHandle(ArcHandle):
    """Handle for an active EntryList instance."""

    def get_category(self, index: int) -> str:
        """Get the entry category."""
        cat = StrBuffer()
        invoke(
            "askar_entry_list_get_category",
            (EntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(cat),
        )
        return str(cat)

    def get_name(self, index: int) -> str:
        """Get the entry name."""
        name = StrBuffer()
        invoke(
            "askar_entry_list_get_name",
            (EntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(name),
        )
        return str(name)

    def get_value(self, index: int) -> ByteBuffer:
        """Get the entry value."""
        val = ByteBuffer()
        invoke(
            "askar_entry_list_get_value",
            (EntryListHandle, c_int32, POINTER(ByteBuffer)),
            self,
            index,
            byref(val),
        )
        return val

    def get_tags(self, index: int) -> dict:
        """Get the entry tags."""
        tags = StrBuffer()
        invoke(
            "askar_entry_list_get_tags",
            (EntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(tags),
        )
        if tags:
            tags = json.loads(tags.value)
            for t in tags:
                if isinstance(tags[t], list):
                    tags[t] = set(tags[t])
        else:
            tags = dict()
        return tags

    def __del__(self):
        """Free the entry set when there are no more references."""
        invoke_dtor("askar_entry_list_free", self)


class KeyEntryListHandle(ArcHandle):
    """Handle for an active KeyEntryList instance."""

    def get_algorithm(self, index: int) -> str:
        """Get the key algorithm."""
        name = StrBuffer()
        invoke(
            "askar_key_entry_list_get_algorithm",
            (KeyEntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(name),
        )
        return str(name)

    def get_name(self, index: int) -> str:
        """Get the key name."""
        name = StrBuffer()
        invoke(
            "askar_key_entry_list_get_name",
            (KeyEntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(name),
        )
        return str(name)

    def get_metadata(self, index: int) -> str:
        """Get for the key metadata."""
        metadata = StrBuffer()
        invoke(
            "askar_key_entry_list_get_metadata",
            (KeyEntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(metadata),
        )
        return str(metadata)

    def get_tags(self, index: int) -> dict:
        """Get the key tags."""
        tags = StrBuffer()
        invoke(
            "askar_key_entry_list_get_tags",
            (KeyEntryListHandle, c_int32, POINTER(c_char_p)),
            self,
            index,
            byref(tags),
        )
        return json.loads(tags.value) if tags else None

    def load_key(self, index: int) -> "LocalKeyHandle":
        """Load the key instance."""
        handle = LocalKeyHandle()
        invoke(
            "askar_key_entry_list_load_local",
            (KeyEntryListHandle, c_int32, POINTER(LocalKeyHandle)),
            self,
            index,
            byref(handle),
        )
        return handle

    def __del__(self):
        """Free the key entry set when there are no more references."""
        invoke_dtor("askar_key_entry_list_free", self)


class LocalKeyHandle(ArcHandle):
    """Handle for an active LocalKey instance."""

    def __del__(self):
        """Free the key when there are no more references."""
        invoke_dtor("askar_key_free", self)


def get_library() -> CDLL:
    """Return the CDLL instance, loading it if necessary."""
    global LIB
    if LIB is None:
        LIB = _load_library("aries_askar")
        _init_logger()
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
        raise AskarError(
            AskarErrorCode.WRAPPER, f"Library not found in path: {lib_path}"
        )
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise AskarError(
            AskarErrorCode.WRAPPER, f"Error loading library: {lib_path}"
        ) from e


def _init_logger():
    logger = logging.getLogger(MODULE_NAME)
    if logging.getLevelName("TRACE") == "Level TRACE":
        # avoid redefining TRACE if another library has added it
        logging.addLevelName(5, "TRACE")

    if not hasattr(_init_logger, "log_cb"):

        @CFUNCTYPE(
            None, c_void_p, c_int32, c_char_p, c_char_p, c_char_p, c_char_p, c_int32
        )
        def _log_cb(
            _context,
            level: int,
            target: c_char_p,
            message: c_char_p,
            module_path: c_char_p,
            file_name: c_char_p,
            line: int,
        ):
            logger.getChild("native." + target.decode().replace("::", ".")).log(
                LOG_LEVELS.get(level, level),
                "\t%s:%d | %s",
                file_name.decode() if file_name else None,
                line,
                message.decode(),
            )

        _init_logger.log_cb = _log_cb

        @CFUNCTYPE(c_int8, c_void_p, c_int32)
        def _enabled_cb(_context, level: int) -> bool:
            return logger.isEnabledFor(LOG_LEVELS.get(level, level))

        _init_logger.enabled_cb = _enabled_cb

    if os.getenv("RUST_LOG"):
        # level from environment
        level = -1
    else:
        # inherit current level from logger
        level = _convert_log_level(logger.level or logger.parent.level)

    invoke(
        "askar_set_custom_logger",
        (c_void_p, c_void_p, c_void_p, c_void_p, c_int32),
        None,  # context
        _init_logger.log_cb,
        _init_logger.enabled_cb,
        None,  # flush
        level,
    )


def set_max_log_level(level: Union[str, int, None]):
    get_library()  # ensure logger is initialized
    set_level = _convert_log_level(level)
    invoke("askar_set_max_log_level", (c_int32,), set_level)


def _convert_log_level(level: Union[str, int, None]):
    if level is None or level == "-1":
        return -1
    else:
        if isinstance(level, str):
            level = level.upper()
        name = logging.getLevelName(level)
        for k, v in LOG_LEVELS.items():
            if logging.getLevelName(v) == name:
                return k
    return 0


def _fulfill_future(fut: asyncio.Future, result, err: Exception = None):
    """Resolve a callback future given the result and exception, if any."""
    if not CALLBACKS.pop(fut, None):
        LOGGER.info("callback already fulfilled")
        return
    if fut.cancelled():
        LOGGER.debug("callback previously cancelled")
    elif err:
        fut.set_exception(err)
    else:
        fut.set_result(result)


def _create_callback(
    cb_type: CFUNCTYPE,
    loop: asyncio.AbstractEventLoop,
    fut: asyncio.Future,
):
    """Create a callback to handle the response from an async library method."""

    def _cb(_id: int, err: int, result=None):
        """Callback function passed to the CFUNCTYPE for invocation."""
        exc = get_current_error() if err else None
        loop.call_soon_threadsafe(_fulfill_future, fut, result, exc)

    res = cb_type(_cb)
    return res


def _get_library_method(name: str, argtypes, *, restype=c_int64):
    method = INVOKE.get(name)
    if not method:
        method = getattr(get_library(), name)
        method.argtypes = argtypes
        method.restype = restype
        INVOKE[name] = method
    return method


def _load_method_arguments(name, argtypes, args):
    """Preload argument values to avoid freeing any intermediate data."""
    if not argtypes:
        return args
    if len(args) != len(argtypes):
        raise ValueError(f"{name}: Arguments length does not match argtypes length")
    return [
        arg if issubclass(argtype, _SimpleCData) else argtype.from_param(arg)
        for (arg, argtype) in zip(args, argtypes)
    ]


def invoke(name, argtypes, *args):
    """Perform a synchronous library function call."""
    method = _get_library_method(name, argtypes)
    args = _load_method_arguments(name, argtypes, args)
    result = method(*args)
    if result:
        raise get_current_error(True)


def invoke_async(name: str, argtypes, *args, return_type=None):
    """Perform an asynchronous library function call."""
    method = _get_library_method(name, (*argtypes, c_void_p, c_int64))
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    cf_args = [c_int64, c_int64]
    if return_type:
        cf_args.append(return_type)
    cb_type = CFUNCTYPE(None, *cf_args)  # could be cached
    cb_res = _create_callback(cb_type, loop, fut)
    args = _load_method_arguments(name, argtypes, args)
    # save a reference to the callback function and arguments to avoid GC
    CALLBACKS[fut] = (cb_res, args)
    result = method(*args, cb_res, 0)  # not making use of callback ID
    if result:
        # FFI must not execute the callback if an error is returned
        err = get_current_error(True)
        _fulfill_future(fut, None, err)
    return fut


def invoke_dtor(name: str, *values, argtypes=None):
    method = INVOKE.get(name)
    if not method:
        lib = get_library()
        if not lib:
            return
        method = getattr(lib, name)
        if argtypes:
            method.argtypes = argtypes
        method.restype = None
        INVOKE[name] = method
    method(*values)


def get_current_error(expect: bool = False) -> Optional[AskarError]:
    """
    Get the error result from the previous failed API method.

    Args:
        expect: Return a default error message if none is found
    """
    err_json = StrBuffer()
    if not LIB or not LIB.askar_get_current_error(byref(err_json)):
        try:
            msg = json.loads(err_json.value)
        except json.JSONDecodeError:
            LOGGER.warning("JSON decode error for askar_get_current_error")
            msg = None
        if msg and "message" in msg and "code" in msg:
            return AskarError(
                AskarErrorCode(msg["code"]), msg["message"], msg.get("extra")
            )
        if not expect:
            return None
    return AskarError(AskarErrorCode.WRAPPER, "Unknown error")


def generate_raw_key(seed: Union[str, bytes] = None) -> str:
    """Generate a new raw store wrapping key."""
    key = StrBuffer()
    invoke(
        "askar_store_generate_raw_key",
        (FfiByteBuffer, POINTER(c_char_p)),
        seed,
        byref(key),
    )
    return str(key)


def version() -> str:
    """Get the version of the installed aries-askar library."""
    lib = get_library()
    lib.askar_version.restype = c_void_p
    return str(StrBuffer(lib.askar_version()))


async def store_open(
    uri: str, key_method: str = None, pass_key: str = None, profile: str = None
) -> StoreHandle:
    """Open an existing Store and return the open handle."""
    return await invoke_async(
        "askar_store_open",
        (FfiStr, FfiStr, FfiStr, FfiStr),
        uri,
        key_method and key_method.lower(),
        pass_key,
        profile,
        return_type=StoreHandle,
    )


async def store_provision(
    uri: str,
    key_method: str = None,
    pass_key: str = None,
    profile: str = None,
    recreate: bool = False,
) -> StoreHandle:
    """Provision a new Store and return the open handle."""
    return await invoke_async(
        "askar_store_provision",
        (FfiStr, FfiStr, FfiStr, FfiStr, c_int8),
        uri,
        key_method and key_method.lower(),
        pass_key,
        profile,
        recreate,
        return_type=StoreHandle,
    )


async def store_create_profile(handle: StoreHandle, name: str = None) -> str:
    """Create a new profile in a Store."""
    return str(
        await invoke_async(
            "askar_store_create_profile",
            (StoreHandle, FfiStr),
            handle,
            name,
            return_type=StrBuffer,
        )
    )


async def store_get_profile_name(handle: StoreHandle) -> str:
    """Get the name of the default Store instance profile."""
    return str(
        await invoke_async(
            "askar_store_get_profile_name",
            (StoreHandle,),
            handle,
            return_type=StrBuffer,
        )
    )


async def store_remove_profile(handle: StoreHandle, name: str) -> bool:
    """Remove an existing profile from a Store."""
    return (
        await invoke_async(
            "askar_store_remove_profile",
            (StoreHandle, FfiStr),
            handle,
            name,
            return_type=c_int8,
        )
        != 0
    )


async def store_rekey(
    handle: StoreHandle,
    key_method: str = None,
    pass_key: str = None,
) -> StoreHandle:
    """Replace the store key on a Store."""
    return await invoke_async(
        "askar_store_rekey",
        (StoreHandle, FfiStr, FfiStr),
        handle,
        key_method and key_method.lower(),
        pass_key,
        return_type=c_int8,
    )


async def store_remove(uri: str) -> bool:
    """Remove an existing Store, if any."""
    return (
        await invoke_async(
            "askar_store_remove",
            (FfiStr,),
            uri,
            return_type=c_int8,
        )
        != 0
    )


async def session_start(
    handle: StoreHandle, profile: Optional[str] = None, as_transaction: bool = False
) -> SessionHandle:
    """Start a new session with an open Store."""
    return await invoke_async(
        "askar_session_start",
        (StoreHandle, FfiStr, c_int8),
        handle,
        profile,
        as_transaction,
        return_type=SessionHandle,
    )


async def session_count(
    handle: SessionHandle, category: str, tag_filter: Union[str, dict] = None
) -> int:
    """Count rows in the Store."""
    return int(
        await invoke_async(
            "askar_session_count",
            (SessionHandle, FfiStr, FfiJson),
            handle,
            category,
            tag_filter,
            return_type=c_int64,
        )
    )


async def session_fetch(
    handle: SessionHandle, category: str, name: str, for_update: bool = False
) -> EntryListHandle:
    """Fetch a row from the Store."""
    return await invoke_async(
        "askar_session_fetch",
        (SessionHandle, FfiStr, FfiStr, c_int8),
        handle,
        category,
        name,
        for_update,
        return_type=EntryListHandle,
    )


async def session_fetch_all(
    handle: SessionHandle,
    category: str,
    tag_filter: Union[str, dict] = None,
    limit: int = None,
    for_update: bool = False,
) -> EntryListHandle:
    """Fetch all matching rows in the Store."""
    return await invoke_async(
        "askar_session_fetch_all",
        (SessionHandle, FfiStr, FfiJson, c_int64, c_int8),
        handle,
        category,
        tag_filter,
        limit if limit is not None else -1,
        for_update,
        return_type=EntryListHandle,
    )


async def session_remove_all(
    handle: SessionHandle,
    category: str,
    tag_filter: Union[str, dict] = None,
) -> int:
    """Remove all matching rows in the Store."""
    return int(
        await invoke_async(
            "askar_session_remove_all",
            (SessionHandle, FfiStr, FfiJson),
            handle,
            category,
            tag_filter,
            return_type=c_int64,
        )
    )


async def session_update(
    handle: SessionHandle,
    operation: EntryOperation,
    category: str,
    name: str,
    value: Union[str, bytes] = None,
    tags: dict = None,
    expiry_ms: Optional[int] = None,
):
    """Update a Store by inserting, updating, or removing a record."""

    return await invoke_async(
        "askar_session_update",
        (SessionHandle, c_int8, FfiStr, FfiStr, FfiByteBuffer, FfiTagsJson, c_int64),
        handle,
        operation.value,
        category,
        name,
        value,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_insert_key(
    handle: SessionHandle,
    key_handle: LocalKeyHandle,
    name: str,
    metadata: str = None,
    tags: dict = None,
    expiry_ms: Optional[int] = None,
):
    return await invoke_async(
        "askar_session_insert_key",
        (SessionHandle, LocalKeyHandle, FfiStr, FfiStr, FfiTagsJson, c_int64),
        handle,
        key_handle,
        name,
        metadata,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_fetch_key(
    handle: SessionHandle, name: str, for_update: bool = False
) -> KeyEntryListHandle:
    return await invoke_async(
        "askar_session_fetch_key",
        (SessionHandle, FfiStr, c_int8),
        handle,
        name,
        for_update,
        return_type=KeyEntryListHandle,
    )


async def session_fetch_all_keys(
    handle: SessionHandle,
    alg: Union[str, KeyAlg] = None,
    thumbprint: str = None,
    tag_filter: Union[str, dict] = None,
    limit: int = None,
    for_update: bool = False,
) -> KeyEntryListHandle:
    """Fetch all matching keys in the Store."""
    if isinstance(alg, KeyAlg):
        alg = alg.value
    return await invoke_async(
        "askar_session_fetch_all_keys",
        (SessionHandle, FfiStr, FfiStr, FfiJson, c_int64, c_int8),
        handle,
        alg,
        thumbprint,
        tag_filter,
        limit if limit is not None else -1,
        for_update,
        return_type=KeyEntryListHandle,
    )


async def session_update_key(
    handle: SessionHandle,
    name: str,
    metadata: str = None,
    tags: dict = None,
    expiry_ms: Optional[int] = None,
):
    await invoke_async(
        "askar_session_update_key",
        (SessionHandle, FfiStr, FfiStr, FfiTagsJson, c_int64),
        handle,
        name,
        metadata,
        tags,
        -1 if expiry_ms is None else expiry_ms,
    )


async def session_remove_key(handle: SessionHandle, name: str):
    await invoke_async(
        "askar_session_remove_key",
        (SessionHandle, FfiStr),
        handle,
        name,
    )


async def scan_start(
    handle: StoreHandle,
    profile: Optional[str],
    category: str,
    tag_filter: Union[str, dict] = None,
    offset: int = None,
    limit: int = None,
) -> ScanHandle:
    """Create a new Scan against the Store."""
    return await invoke_async(
        "askar_scan_start",
        (StoreHandle, FfiStr, FfiStr, FfiJson, c_int64, c_int64),
        handle,
        profile,
        category,
        tag_filter,
        offset or 0,
        limit if limit is not None else -1,
        return_type=ScanHandle,
    )


async def scan_next(handle: ScanHandle) -> EntryListHandle:
    return await invoke_async(
        "askar_scan_next", (ScanHandle,), handle, return_type=EntryListHandle
    )


def entry_list_count(handle: EntryListHandle) -> int:
    len = c_int32()
    invoke(
        "askar_entry_list_count",
        (EntryListHandle, POINTER(c_int32)),
        handle,
        byref(len),
    )
    return len.value


def key_entry_list_count(handle: KeyEntryListHandle) -> int:
    len = c_int32()
    invoke(
        "askar_key_entry_list_count",
        (KeyEntryListHandle, POINTER(c_int32)),
        handle,
        byref(len),
    )
    return len.value


def key_generate(alg: Union[str, KeyAlg], ephemeral: bool = False) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_generate",
        (FfiStr, c_int8, POINTER(LocalKeyHandle)),
        alg,
        ephemeral,
        byref(handle),
    )
    return handle


def key_from_seed(
    alg: Union[str, KeyAlg],
    seed: Union[str, bytes, ByteBuffer],
    method: Union[str, SeedMethod] = None,
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(method, SeedMethod):
        method = method.value
    invoke(
        "askar_key_from_seed",
        (FfiStr, FfiByteBuffer, FfiStr, POINTER(LocalKeyHandle)),
        alg,
        seed,
        method,
        byref(handle),
    )
    return handle


def key_from_public_bytes(
    alg: Union[str, KeyAlg], public: Union[bytes, ByteBuffer]
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_public_bytes",
        (FfiStr, FfiByteBuffer, POINTER(LocalKeyHandle)),
        alg,
        public,
        byref(handle),
    )
    return handle


def key_get_public_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_get_public_bytes",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(buf),
    )
    return buf


def key_from_secret_bytes(
    alg: Union[str, KeyAlg], secret: Union[bytes, ByteBuffer]
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_secret_bytes",
        (FfiStr, FfiByteBuffer, POINTER(LocalKeyHandle)),
        alg,
        secret,
        byref(handle),
    )
    return handle


def key_get_secret_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_get_secret_bytes",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(buf),
    )
    return buf


def key_from_jwk(jwk: Union[dict, str, bytes]) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(jwk, dict):
        jwk = json.dumps(jwk)
    invoke(
        "askar_key_from_jwk",
        (FfiByteBuffer, POINTER(LocalKeyHandle)),
        jwk,
        byref(handle),
    )
    return handle


def key_convert(handle: LocalKeyHandle, alg: Union[str, KeyAlg]) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_convert",
        (LocalKeyHandle, FfiStr, POINTER(LocalKeyHandle)),
        handle,
        alg,
        byref(key),
    )
    return key


def key_exchange(
    alg: Union[str, KeyAlg], sk_handle: LocalKeyHandle, pk_handle: LocalKeyHandle
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_from_key_exchange",
        (FfiStr, LocalKeyHandle, LocalKeyHandle, POINTER(LocalKeyHandle)),
        alg,
        sk_handle,
        pk_handle,
        byref(key),
    )
    return key


def key_get_algorithm(handle: LocalKeyHandle) -> str:
    alg = StrBuffer()
    invoke(
        "askar_key_get_algorithm",
        (LocalKeyHandle, POINTER(c_char_p)),
        handle,
        byref(alg),
    )
    return str(alg)


def key_get_ephemeral(handle: LocalKeyHandle) -> bool:
    eph = c_int8()
    invoke(
        "askar_key_get_ephemeral",
        (LocalKeyHandle, POINTER(c_int8)),
        handle,
        byref(eph),
    )
    return eph.value != 0


def key_get_jwk_public(handle: LocalKeyHandle, alg: Union[str, KeyAlg] = None) -> str:
    jwk = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_get_jwk_public",
        (LocalKeyHandle, FfiStr, POINTER(c_char_p)),
        handle,
        alg,
        byref(jwk),
    )
    return str(jwk)


def key_get_jwk_secret(handle: LocalKeyHandle) -> ByteBuffer:
    sec = ByteBuffer()
    invoke(
        "askar_key_get_jwk_secret",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(sec),
    )
    return sec


def key_get_jwk_thumbprint(
    handle: LocalKeyHandle, alg: Union[str, KeyAlg] = None
) -> str:
    thumb = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    invoke(
        "askar_key_get_jwk_thumbprint",
        (LocalKeyHandle, FfiStr, POINTER(c_char_p)),
        handle,
        alg,
        byref(thumb),
    )
    return str(thumb)


def key_aead_get_params(handle: LocalKeyHandle) -> AeadParams:
    params = AeadParams()
    invoke(
        "askar_key_aead_get_params",
        (LocalKeyHandle, POINTER(AeadParams)),
        handle,
        byref(params),
    )
    return params


def key_aead_random_nonce(handle: LocalKeyHandle) -> ByteBuffer:
    nonce = ByteBuffer()
    invoke(
        "askar_key_aead_random_nonce",
        (LocalKeyHandle, POINTER(ByteBuffer)),
        handle,
        byref(nonce),
    )
    return nonce


def key_aead_encrypt(
    handle: LocalKeyHandle,
    input: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
    aad: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    enc = Encrypted()
    invoke(
        "askar_key_aead_encrypt",
        (
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(Encrypted),
        ),
        handle,
        input,
        nonce,
        aad,
        byref(enc),
    )
    return enc


def key_aead_decrypt(
    handle: LocalKeyHandle,
    ciphertext: Union[bytes, ByteBuffer, Encrypted],
    nonce: Union[bytes, ByteBuffer],
    tag: Optional[Union[bytes, ByteBuffer]],
    aad: Optional[Union[bytes, ByteBuffer]],
) -> ByteBuffer:
    dec = ByteBuffer()
    if isinstance(ciphertext, Encrypted):
        nonce = ciphertext.nonce
        ciphertext = ciphertext.ciphertext_tag
    invoke(
        "askar_key_aead_decrypt",
        (
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        handle,
        ciphertext,
        nonce,
        tag,
        aad,
        byref(dec),
    )
    return dec


def key_sign_message(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    sig_type: Optional[str],
) -> ByteBuffer:
    sig = ByteBuffer()
    invoke(
        "askar_key_sign_message",
        (LocalKeyHandle, FfiByteBuffer, FfiStr, POINTER(ByteBuffer)),
        handle,
        message,
        sig_type,
        byref(sig),
    )
    return sig


def key_verify_signature(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    signature: Union[bytes, ByteBuffer],
    sig_type: Optional[str],
) -> bool:
    verify = c_int8()
    invoke(
        "askar_key_verify_signature",
        (LocalKeyHandle, FfiByteBuffer, FfiByteBuffer, FfiStr, POINTER(c_int8)),
        handle,
        message,
        signature,
        sig_type,
        byref(verify),
    )
    return verify.value != 0


def key_wrap_key(
    handle: LocalKeyHandle,
    other: LocalKeyHandle,
    nonce: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    wrapped = Encrypted()
    invoke(
        "askar_key_wrap_key",
        (LocalKeyHandle, LocalKeyHandle, FfiByteBuffer, POINTER(Encrypted)),
        handle,
        other,
        nonce,
        byref(wrapped),
    )
    return wrapped


def key_unwrap_key(
    handle: LocalKeyHandle,
    alg: Union[str, KeyAlg],
    ciphertext: Union[bytes, ByteBuffer, Encrypted],
    nonce: Union[bytes, ByteBuffer],
    tag: Optional[Union[bytes, ByteBuffer]],
) -> LocalKeyHandle:
    result = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(ciphertext, Encrypted):
        ciphertext = ciphertext.ciphertext_tag
    invoke(
        "askar_key_unwrap_key",
        (
            LocalKeyHandle,
            FfiStr,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(LocalKeyHandle),
        ),
        handle,
        alg,
        ciphertext,
        nonce,
        tag,
        byref(result),
    )
    return result


def key_crypto_box_random_nonce() -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_random_nonce",
        (POINTER(ByteBuffer),),
        byref(buf),
    )
    return buf


def key_crypto_box(
    recip_handle: LocalKeyHandle,
    sender_handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box",
        (
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        recip_handle,
        sender_handle,
        message,
        nonce,
        byref(buf),
    )
    return buf


def key_crypto_box_open(
    recip_handle: LocalKeyHandle,
    sender_handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_open",
        (
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            POINTER(ByteBuffer),
        ),
        recip_handle,
        sender_handle,
        message,
        nonce,
        byref(buf),
    )
    return buf


def key_crypto_box_seal(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_seal",
        (LocalKeyHandle, FfiByteBuffer, POINTER(ByteBuffer)),
        handle,
        message,
        byref(buf),
    )
    return buf


def key_crypto_box_seal_open(
    handle: LocalKeyHandle,
    ciphertext: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    invoke(
        "askar_key_crypto_box_seal_open",
        (LocalKeyHandle, FfiByteBuffer, POINTER(ByteBuffer)),
        handle,
        ciphertext,
        byref(buf),
    )
    return buf


def key_derive_ecdh_es(
    key_alg: Union[str, KeyAlg],
    ephem_key: LocalKeyHandle,
    receiver_key: LocalKeyHandle,
    alg_id: Union[bytes, str, ByteBuffer],
    apu: Union[bytes, str, ByteBuffer],
    apv: Union[bytes, str, ByteBuffer],
    receive: bool,
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(key_alg, KeyAlg):
        key_alg = key_alg.value
    invoke(
        "askar_key_derive_ecdh_es",
        (
            FfiStr,
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            c_int8,
            POINTER(LocalKeyHandle),
        ),
        key_alg,
        ephem_key,
        receiver_key,
        alg_id,
        apu,
        apv,
        receive,
        byref(key),
    )
    return key


def key_derive_ecdh_1pu(
    key_alg: Union[str, KeyAlg],
    ephem_key: LocalKeyHandle,
    sender_key: LocalKeyHandle,
    receiver_key: LocalKeyHandle,
    alg_id: Union[bytes, str, ByteBuffer],
    apu: Union[bytes, str, ByteBuffer],
    apv: Union[bytes, str, ByteBuffer],
    cc_tag: Optional[Union[bytes, ByteBuffer]],
    receive: bool,
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(key_alg, KeyAlg):
        key_alg = key_alg.value
    invoke(
        "askar_key_derive_ecdh_1pu",
        (
            FfiStr,
            LocalKeyHandle,
            LocalKeyHandle,
            LocalKeyHandle,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            FfiByteBuffer,
            c_int8,
            POINTER(LocalKeyHandle),
        ),
        key_alg,
        ephem_key,
        sender_key,
        receiver_key,
        alg_id,
        apu,
        apv,
        cc_tag,
        receive,
        byref(key),
    )
    return key
