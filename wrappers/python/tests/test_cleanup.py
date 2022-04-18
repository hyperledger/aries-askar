from ctypes import c_char, c_char_p, c_size_t, c_ubyte, pointer
from unittest import mock

from aries_askar.bindings.handle import ArcHandle
from aries_askar.bindings.lib import ByteBuffer, RawBuffer, StrBuffer


def test_cleanup_handle():
    logged = []

    class Handle(ArcHandle):
        @classmethod
        def _cleanup(cls, handle: c_size_t):
            logged.append(handle.value)

    h = Handle()
    assert not h.value
    del h
    assert not logged

    h = Handle()
    h.value = 99
    del h
    assert logged == [(99)]


def test_cleanup_bytebuffer():
    logged = []

    def cleanup(buffer: RawBuffer):
        logged.append((buffer.len, buffer.data.contents.value if buffer.data else None))

    with mock.patch.object(ByteBuffer, "_cleanup", cleanup):
        b = ByteBuffer()
        del b
        assert not logged

        c = c_ubyte(99)
        b = ByteBuffer()
        b.buffer = RawBuffer(len=1, data=pointer(c))
        del b
        assert logged == [(1, 99)]


def test_cleanup_strbuffer():
    logged = []

    def cleanup(buffer: c_char_p):
        logged.append(buffer.value)

    with mock.patch.object(StrBuffer, "_cleanup", cleanup):
        s = StrBuffer()
        del s
        assert not logged

        s = StrBuffer()
        c = c_char(ord("a"))
        s.buffer = pointer(c)
        del s
        assert logged == [b"a"]
