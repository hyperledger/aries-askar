"""Low-level interaction with the aries-askar library."""

import asyncio
import json
import logging
import os
import sys
from ctypes import (
    Array,
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    byref,
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
LIB: CDLL = None
LOGGER = logging.getLogger(__name__)
LOG_LEVELS = {
    1: logging.ERROR,
    2: logging.WARNING,
    3: logging.INFO,
    4: logging.DEBUG,
}
MODULE_NAME = __name__.split(".")[0]


class StoreHandle(c_size_t):
    """Index of an active Store instance."""

    def __repr__(self) -> str:
        """Format store handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    async def close(self):
        """Close the store, waiting for any active connections."""
        if not getattr(self, "_closed", False):
            await do_call_async("askar_store_close", self)
            setattr(self, "_closed", True)

    def __del__(self):
        """Close the store when there are no more references to this object."""
        if not getattr(self, "_closed", False) and self:
            do_call("askar_store_close", self, c_void_p())


class SessionHandle(c_size_t):
    """Index of an active Session/Transaction instance."""

    def __repr__(self) -> str:
        """Format session handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    async def close(self, commit: bool = False):
        """Close the session."""
        if not getattr(self, "_closed", False):
            await do_call_async(
                "askar_session_close",
                self,
                c_int8(commit),
            )
            setattr(self, "_closed", True)

    def __del__(self):
        """Close the session when there are no more references to this object."""
        if not getattr(self, "_closed", False) and self:
            do_call("askar_session_close", self, c_int8(0), c_void_p())


class ScanHandle(c_size_t):
    """Index of an active Store scan instance."""

    def __repr__(self) -> str:
        """Format scan handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    def __del__(self):
        """Close the scan when there are no more references to this object."""
        if self:
            get_library().askar_scan_free(self)


class EntryListHandle(c_size_t):
    """Pointer to an active EntryList instance."""

    def get_category(self, index: int) -> str:
        """Get the entry category."""
        cat = StrBuffer()
        do_call(
            "askar_entry_list_get_category",
            self,
            c_int32(index),
            byref(cat),
        )
        return str(cat)

    def get_name(self, index: int) -> str:
        """Get the entry name."""
        name = StrBuffer()
        do_call(
            "askar_entry_list_get_name",
            self,
            c_int32(index),
            byref(name),
        )
        return str(name)

    def get_value(self, index: int) -> memoryview:
        """Get the entry value."""
        val = ByteBuffer()
        do_call("askar_entry_list_get_value", self, c_int32(index), byref(val))
        return memoryview(val.raw)

    def get_tags(self, index: int) -> dict:
        """Get the entry tags."""
        tags = StrBuffer()
        do_call(
            "askar_entry_list_get_tags",
            self,
            c_int32(index),
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

    def __repr__(self) -> str:
        """Format entry list handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    def __del__(self):
        """Free the entry set when there are no more references."""
        if self:
            get_library().askar_entry_list_free(self)


class KeyEntryListHandle(c_size_t):
    """Pointer to an active KeyEntryList instance."""

    def get_algorithm(self, index: int) -> str:
        """Get the key algorithm."""
        name = StrBuffer()
        do_call(
            "askar_key_entry_list_get_algorithm",
            self,
            c_int32(index),
            byref(name),
        )
        return str(name)

    def get_name(self, index: int) -> str:
        """Get the key name."""
        name = StrBuffer()
        do_call(
            "askar_key_entry_list_get_name",
            self,
            c_int32(index),
            byref(name),
        )
        return str(name)

    def get_metadata(self, index: int) -> str:
        """Get for the key metadata."""
        metadata = StrBuffer()
        do_call(
            "askar_key_entry_list_get_metadata",
            self,
            c_int32(index),
            byref(metadata),
        )
        return str(metadata)

    def get_tags(self, index: int) -> dict:
        """Get the key tags."""
        tags = StrBuffer()
        do_call(
            "askar_key_entry_list_get_tags",
            self,
            c_int32(index),
            byref(tags),
        )
        return json.loads(tags.value) if tags else None

    def load_key(self, index: int) -> "LocalKeyHandle":
        """Load the key instance."""
        handle = LocalKeyHandle()
        do_call(
            "askar_key_entry_list_load_local",
            self,
            c_int32(index),
            byref(handle),
        )
        return handle

    def __repr__(self) -> str:
        """Format key entry list handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    def __del__(self):
        """Free the key entry set when there are no more references."""
        if self:
            get_library().askar_key_entry_list_free(self)


class LocalKeyHandle(c_size_t):
    """Pointer to an active LocalKey instance."""

    def __repr__(self) -> str:
        """Format key handle as a string."""
        return f"{self.__class__.__name__}({self.value})"

    def __del__(self):
        """Free the key when there are no more references."""
        if self:
            get_library().askar_key_free(self)


class FfiByteBuffer(Structure):
    """A byte buffer allocated by python."""

    _fields_ = [
        ("len", c_int64),
        ("value", POINTER(c_ubyte)),
    ]


class RawBuffer(Structure):
    """A byte buffer allocated by the library."""

    _fields_ = [
        ("len", c_int64),
        ("data", c_void_p),
    ]


class ByteBuffer(Structure):
    """A managed byte buffer allocated by the library."""

    _fields_ = [("buffer", RawBuffer)]

    @property
    def raw(self) -> Array:
        ret = (c_ubyte * self.buffer.len).from_address(self.buffer.data)
        setattr(ret, "_ref_", self)  # ensure buffer is not dropped
        return ret

    def __bytes__(self) -> bytes:
        return bytes(self.raw)

    def __repr__(self) -> str:
        """Format byte buffer as a string."""
        return repr(bytes(self))

    def __del__(self):
        """Call the byte buffer destructor when this instance is released."""
        get_library().askar_buffer_free(self.buffer)


class StrBuffer(c_char_p):
    """A string allocated by the library."""

    @classmethod
    def from_param(cls):
        """Returns the type ctypes should use for loading the result."""
        return c_void_p

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
        get_library().askar_string_free(self)


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
        arr = (c_ubyte * self.buffer.len).from_address(self.buffer.data)
        return bytes(arr[idx])

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
        get_library().askar_buffer_free(self.buffer)


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

    def _enabled(_context, level: int) -> bool:
        return logger.isEnabledFor(LOG_LEVELS.get(level, level))

    def _log(
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

    _init_logger.enabled_cb = CFUNCTYPE(c_int8, c_void_p, c_int32)(_enabled)

    _init_logger.log_cb = CFUNCTYPE(
        None, c_void_p, c_int32, c_char_p, c_char_p, c_char_p, c_char_p, c_int32
    )(_log)

    if os.getenv("RUST_LOG"):
        # level from environment
        level = -1
    else:
        # inherit current level from logger
        level = _convert_log_level(logger.level or logger.parent.level)

    do_call(
        "askar_set_custom_logger",
        c_void_p(),  # context
        _init_logger.log_cb,
        _init_logger.enabled_cb,
        c_void_p(),  # flush
        c_int32(level),
    )


def set_max_log_level(level: Union[str, int, None]):
    get_library()  # ensure logger is initialized
    set_level = _convert_log_level(level)
    do_call("askar_set_max_log_level", c_int32(set_level))


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
    lib_fn.restype = c_int64
    result = lib_fn(*args)
    if result:
        raise get_current_error(True)


def do_call_async(
    fn_name, *args, return_type=None, post_process=None
) -> asyncio.Future:
    """Perform an asynchronous library function call."""
    lib_fn = getattr(get_library(), fn_name)
    lib_fn.restype = c_int64
    loop = asyncio.get_event_loop()
    fut = loop.create_future()
    cf_args = [None, c_int64, c_int64]
    if return_type:
        cf_args.append(return_type)
    cb_type = CFUNCTYPE(*cf_args)  # could be cached
    cb_res = _create_callback(cb_type, fut, post_process)
    # keep a reference to the callback function to avoid it being freed
    CALLBACKS[fut] = (loop, cb_res)
    result = lib_fn(*args, cb_res, c_void_p())  # not making use of callback ID
    if result:
        # callback will not be executed
        if CALLBACKS.pop(fut):
            fut.set_exception(get_current_error())
    return fut


def encode_str(arg: Optional[Union[str, bytes]]) -> c_char_p:
    """
    Encode an optional input argument as a string.

    Returns: None if the argument is None, otherwise the value encoded utf-8.
    """
    if arg is None:
        return c_char_p()
    if isinstance(arg, str):
        arg = arg.encode("utf-8")
    return c_char_p(arg)


def encode_bytes(
    arg: Optional[Union[str, bytes, ByteBuffer, FfiByteBuffer]]
) -> Union[FfiByteBuffer, ByteBuffer]:
    if isinstance(arg, ByteBuffer) or isinstance(arg, FfiByteBuffer):
        return arg
    buf = FfiByteBuffer()
    if isinstance(arg, memoryview):
        buf.len = arg.nbytes
        if arg.contiguous and not arg.readonly:
            buf.value = (c_ubyte * buf.len).from_buffer(arg.obj)
        else:
            buf.value = (c_ubyte * buf.len).from_buffer_copy(arg.obj)
    elif isinstance(arg, bytearray):
        buf.len = len(arg)
        if buf.len > 0:
            buf.value = (c_ubyte * buf.len).from_buffer(arg)
    elif arg is not None:
        if isinstance(arg, str):
            arg = arg.encode("utf-8")
        buf.len = len(arg)
        if buf.len > 0:
            buf.value = (c_ubyte * buf.len).from_buffer_copy(arg)
    return buf


def encode_tags(tags: Optional[dict]) -> c_char_p:
    """Encode the tags as a JSON string."""
    if tags:
        tags = json.dumps(
            {
                name: (list(value) if isinstance(value, set) else value)
                for name, value in tags.items()
            }
        )
    else:
        tags = None
    return encode_str(tags)


def get_current_error(expect: bool = False) -> Optional[AskarError]:
    """
    Get the error result from the previous failed API method.

    Args:
        expect: Return a default error message if none is found
    """
    err_json = StrBuffer()
    if not get_library().askar_get_current_error(byref(err_json)):
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
    do_call("askar_store_generate_raw_key", encode_bytes(seed), byref(key))
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
    return await do_call_async(
        "askar_store_open",
        encode_str(uri),
        encode_str(key_method and key_method.lower()),
        encode_str(pass_key),
        encode_str(profile),
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
    return await do_call_async(
        "askar_store_provision",
        encode_str(uri),
        encode_str(key_method and key_method.lower()),
        encode_str(pass_key),
        encode_str(profile),
        c_int8(recreate),
        return_type=StoreHandle,
    )


async def store_create_profile(handle: StoreHandle, name: str = None) -> str:
    """Create a new profile in a Store."""
    return str(
        await do_call_async(
            "askar_store_create_profile",
            handle,
            encode_str(name),
            return_type=StrBuffer,
        )
    )


async def store_get_profile_name(handle: StoreHandle) -> str:
    """Get the name of the default Store instance profile."""
    return str(
        await do_call_async(
            "askar_store_get_profile_name",
            handle,
            return_type=StrBuffer,
        )
    )


async def store_remove_profile(handle: StoreHandle, name: str) -> bool:
    """Remove an existing profile from a Store."""
    return (
        await do_call_async(
            "askar_store_remove_profile",
            handle,
            encode_str(name),
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
    return await do_call_async(
        "askar_store_rekey",
        handle,
        encode_str(key_method and key_method.lower()),
        encode_str(pass_key),
    )


async def store_remove(uri: str) -> bool:
    """Remove an existing Store, if any."""
    return (
        await do_call_async(
            "askar_store_remove",
            encode_str(uri),
            return_type=c_int8,
        )
        != 0
    )


async def session_start(
    handle: StoreHandle, profile: Optional[str] = None, as_transaction: bool = False
) -> SessionHandle:
    """Start a new session with an open Store."""
    return await do_call_async(
        "askar_session_start",
        handle,
        encode_str(profile),
        c_int8(as_transaction),
        return_type=SessionHandle,
    )


async def session_count(
    handle: SessionHandle, category: str, tag_filter: Union[str, dict] = None
) -> int:
    """Count rows in the Store."""
    category = encode_str(category)
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    tag_filter = encode_str(tag_filter)
    return int(
        await do_call_async(
            "askar_session_count", handle, category, tag_filter, return_type=c_int64
        )
    )


async def session_fetch(
    handle: SessionHandle, category: str, name: str, for_update: bool = False
) -> EntryListHandle:
    """Fetch a row from the Store."""
    category = encode_str(category)
    name = encode_str(name)
    return await do_call_async(
        "askar_session_fetch",
        handle,
        category,
        name,
        c_int8(for_update),
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
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    return await do_call_async(
        "askar_session_fetch_all",
        handle,
        encode_str(category),
        encode_str(tag_filter),
        c_int64(limit if limit is not None else -1),
        c_int8(for_update),
        return_type=EntryListHandle,
    )


async def session_remove_all(
    handle: SessionHandle,
    category: str,
    tag_filter: Union[str, dict] = None,
) -> int:
    """Remove all matching rows in the Store."""
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    return int(
        await do_call_async(
            "askar_session_remove_all",
            handle,
            encode_str(category),
            encode_str(tag_filter),
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

    return await do_call_async(
        "askar_session_update",
        handle,
        c_int8(operation.value),
        encode_str(category),
        encode_str(name),
        encode_bytes(value),
        encode_tags(tags),
        c_int64(-1 if expiry_ms is None else expiry_ms),
    )


async def session_insert_key(
    handle: SessionHandle,
    key_handle: LocalKeyHandle,
    name: str,
    metadata: str = None,
    tags: dict = None,
    expiry_ms: Optional[int] = None,
):
    await do_call_async(
        "askar_session_insert_key",
        handle,
        key_handle,
        encode_str(name),
        encode_str(metadata),
        encode_tags(tags),
        c_int64(-1 if expiry_ms is None else expiry_ms),
        return_type=c_void_p,
    )


async def session_fetch_key(
    handle: SessionHandle, name: str, for_update: bool = False
) -> Optional[KeyEntryListHandle]:
    ptr = await do_call_async(
        "askar_session_fetch_key",
        handle,
        encode_str(name),
        c_int8(for_update),
        return_type=c_void_p,
    )
    if ptr:
        return KeyEntryListHandle(ptr)


async def session_fetch_all_keys(
    handle: SessionHandle,
    alg: Union[str, KeyAlg] = None,
    thumbprint: str = None,
    tag_filter: Union[str, dict] = None,
    limit: int = None,
    for_update: bool = False,
) -> EntryListHandle:
    """Fetch all matching keys in the Store."""
    if isinstance(alg, KeyAlg):
        alg = alg.value
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    return await do_call_async(
        "askar_session_fetch_all_keys",
        handle,
        encode_str(alg),
        encode_str(thumbprint),
        encode_str(tag_filter),
        c_int64(limit if limit is not None else -1),
        c_int8(for_update),
        return_type=KeyEntryListHandle,
    )


async def session_update_key(
    handle: SessionHandle,
    name: str,
    metadata: str = None,
    tags: dict = None,
    expiry_ms: Optional[int] = None,
):
    await do_call_async(
        "askar_session_update_key",
        handle,
        encode_str(name),
        encode_str(metadata),
        encode_tags(tags),
        c_int64(-1 if expiry_ms is None else expiry_ms),
    )


async def session_remove_key(handle: SessionHandle, name: str):
    await do_call_async(
        "askar_session_remove_key",
        handle,
        encode_str(name),
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
    if isinstance(tag_filter, dict):
        tag_filter = json.dumps(tag_filter)
    tag_filter = encode_str(tag_filter)
    return await do_call_async(
        "askar_scan_start",
        handle,
        encode_str(profile),
        encode_str(category),
        tag_filter,
        c_int64(offset or 0),
        c_int64(limit if limit is not None else -1),
        return_type=ScanHandle,
    )


async def scan_next(handle: StoreHandle) -> Optional[EntryListHandle]:
    handle = await do_call_async("askar_scan_next", handle, return_type=EntryListHandle)
    return handle or None


def entry_list_count(handle: EntryListHandle) -> int:
    len = c_int32()
    do_call("askar_entry_list_count", handle, byref(len))
    return len.value


def key_entry_list_count(handle: EntryListHandle) -> int:
    len = c_int32()
    do_call("askar_key_entry_list_count", handle, byref(len))
    return len.value


def key_generate(alg: Union[str, KeyAlg], ephemeral: bool = False) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call("askar_key_generate", encode_str(alg), c_int8(ephemeral), byref(handle))
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
    do_call(
        "askar_key_from_seed",
        encode_str(alg),
        encode_bytes(seed),
        encode_str(method),
        byref(handle),
    )
    return handle


def key_from_public_bytes(
    alg: Union[str, KeyAlg], public: Union[bytes, ByteBuffer]
) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call(
        "askar_key_from_public_bytes",
        encode_str(alg),
        encode_bytes(public),
        byref(handle),
    )
    return handle


def key_get_public_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    do_call(
        "askar_key_get_public_bytes",
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
    do_call(
        "askar_key_from_secret_bytes",
        encode_str(alg),
        encode_bytes(secret),
        byref(handle),
    )
    return handle


def key_get_secret_bytes(handle: LocalKeyHandle) -> ByteBuffer:
    buf = ByteBuffer()
    do_call(
        "askar_key_get_secret_bytes",
        handle,
        byref(buf),
    )
    return buf


def key_from_jwk(jwk: Union[dict, str, bytes]) -> LocalKeyHandle:
    handle = LocalKeyHandle()
    if isinstance(jwk, dict):
        jwk = json.dumps(jwk)
    do_call("askar_key_from_jwk", encode_bytes(jwk), byref(handle))
    return handle


def key_convert(handle: LocalKeyHandle, alg: Union[str, KeyAlg]) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call("askar_key_convert", handle, encode_str(alg), byref(key))
    return key


def key_exchange(
    alg: Union[str, KeyAlg], sk_handle: LocalKeyHandle, pk_handle: LocalKeyHandle
) -> LocalKeyHandle:
    key = LocalKeyHandle()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call(
        "askar_key_from_key_exchange", encode_str(alg), sk_handle, pk_handle, byref(key)
    )
    return key


def key_get_algorithm(handle: LocalKeyHandle) -> str:
    alg = StrBuffer()
    do_call("askar_key_get_algorithm", handle, byref(alg))
    return str(alg)


def key_get_ephemeral(handle: LocalKeyHandle) -> bool:
    eph = c_int8()
    do_call("askar_key_get_ephemeral", handle, byref(eph))
    return eph.value != 0


def key_get_jwk_public(handle: LocalKeyHandle, alg: Union[str, KeyAlg] = None) -> str:
    jwk = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call("askar_key_get_jwk_public", handle, encode_str(alg), byref(jwk))
    return str(jwk)


def key_get_jwk_secret(handle: LocalKeyHandle) -> ByteBuffer:
    sec = ByteBuffer()
    do_call("askar_key_get_jwk_secret", handle, byref(sec))
    return sec


def key_get_jwk_thumbprint(
    handle: LocalKeyHandle, alg: Union[str, KeyAlg] = None
) -> str:
    thumb = StrBuffer()
    if isinstance(alg, KeyAlg):
        alg = alg.value
    do_call("askar_key_get_jwk_thumbprint", handle, encode_str(alg), byref(thumb))
    return str(thumb)


def key_aead_get_params(handle: LocalKeyHandle) -> AeadParams:
    params = AeadParams()
    do_call("askar_key_aead_get_params", handle, byref(params))
    return params


def key_aead_random_nonce(handle: LocalKeyHandle) -> ByteBuffer:
    nonce = ByteBuffer()
    do_call("askar_key_aead_random_nonce", handle, byref(nonce))
    return nonce


def key_aead_encrypt(
    handle: LocalKeyHandle,
    input: Union[bytes, str, ByteBuffer],
    nonce: Union[bytes, ByteBuffer],
    aad: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    enc = Encrypted()
    do_call(
        "askar_key_aead_encrypt",
        handle,
        encode_bytes(input),
        encode_bytes(nonce),
        encode_bytes(aad),
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
        ciphertext = ciphertext.ciphertext_tag
    do_call(
        "askar_key_aead_decrypt",
        handle,
        encode_bytes(ciphertext),
        encode_bytes(nonce),
        encode_bytes(tag),
        encode_bytes(aad),
        byref(dec),
    )
    return dec


def key_sign_message(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
    sig_type: Optional[str],
) -> ByteBuffer:
    sig = ByteBuffer()
    do_call(
        "askar_key_sign_message",
        handle,
        encode_bytes(message),
        encode_str(sig_type),
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
    do_call(
        "askar_key_verify_signature",
        handle,
        encode_bytes(message),
        encode_bytes(signature),
        encode_str(sig_type),
        byref(verify),
    )
    return verify.value != 0


def key_wrap_key(
    handle: LocalKeyHandle,
    other: LocalKeyHandle,
    nonce: Optional[Union[bytes, ByteBuffer]],
) -> Encrypted:
    wrapped = Encrypted()
    do_call(
        "askar_key_wrap_key",
        handle,
        other,
        encode_bytes(nonce),
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
    do_call(
        "askar_key_unwrap_key",
        handle,
        encode_str(alg),
        encode_bytes(ciphertext),
        encode_bytes(nonce),
        encode_bytes(tag),
        byref(result),
    )
    return result


def key_crypto_box_random_nonce() -> ByteBuffer:
    buf = ByteBuffer()
    do_call(
        "askar_key_crypto_box_random_nonce",
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
    do_call(
        "askar_key_crypto_box",
        recip_handle,
        sender_handle,
        encode_bytes(message),
        encode_bytes(nonce),
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
    do_call(
        "askar_key_crypto_box_open",
        recip_handle,
        sender_handle,
        encode_bytes(message),
        encode_bytes(nonce),
        byref(buf),
    )
    return buf


def key_crypto_box_seal(
    handle: LocalKeyHandle,
    message: Union[bytes, str, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    do_call(
        "askar_key_crypto_box_seal",
        handle,
        encode_bytes(message),
        byref(buf),
    )
    return buf


def key_crypto_box_seal_open(
    handle: LocalKeyHandle,
    ciphertext: Union[bytes, ByteBuffer],
) -> ByteBuffer:
    buf = ByteBuffer()
    do_call(
        "askar_key_crypto_box_seal_open",
        handle,
        encode_bytes(ciphertext),
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
    do_call(
        "askar_key_derive_ecdh_es",
        encode_str(key_alg),
        ephem_key,
        receiver_key,
        encode_bytes(alg_id),
        encode_bytes(apu),
        encode_bytes(apv),
        c_int8(receive),
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
    do_call(
        "askar_key_derive_ecdh_1pu",
        encode_str(key_alg),
        ephem_key,
        sender_key,
        receiver_key,
        encode_bytes(alg_id),
        encode_bytes(apu),
        encode_bytes(apv),
        encode_bytes(cc_tag),
        c_int8(receive),
        byref(key),
    )
    return key
