"""
protocol.py
===========
Application-level wire protocol for the P2P Network.

Course : CSE 433 - Blockchain & Distributed Security Lab
Author : <Your Name> - University of Asia Pacific

ROLE OF THIS MODULE
-------------------
protocol.py is the pure "language" of the network. It converts Python
dictionaries into framed bytes on the wire, and framed bytes back into
dictionaries. It holds NO sockets, NO threads, and NO GUI references,
which keeps it fully independent and testable on its own (run:
`python protocol.py` for the built-in self-test suite).

FRAMING RULE
------------
TCP is a raw byte stream with no built-in message boundaries. To give
the receiver an exact boundary for every message, each JSON payload is
prefixed with a 4-byte unsigned big-endian length:

    +---------------------+------------------------------+
    |  4-byte length (N)  |  N bytes of UTF-8 JSON data  |
    |  struct.pack('>I')  |  (the actual payload)        |
    +---------------------+------------------------------+

BINARY FILE TRANSFER RULE (two-phase)
------------------------------------
    Phase 1 : one framed JSON metadata message
              {"type": "file", "filename": ..., "filesize": ...}
    Phase 2 : exactly `filesize` raw bytes streamed in CHUNK_SIZE
              (64 KiB) pieces, written by the receiver into
              ./downloads/  (transfer engine built in Step 7).

CONTRACT WITH THE REST OF THE PROJECT
------------------------------------
    * p2p_node.py calls send_frame()/recv_frame()/recv_exact() and the
      build_*() constructors for every message it exchanges.
    * main.py only ever sees plain dicts and human-readable strings.
    * Every failure surfaces as a ProtocolError subclass, so the node
      layer (Step 8) catches ONE family of exceptions to handle
      disconnects, corruption and hostile input uniformly.
"""

import json
import os
import struct
import sys

# ======================================================================
# SECTION 1 - WIRE CONSTANTS (the single source of truth for the protocol)
# ======================================================================

#: Length prefix format: 4-byte unsigned integer, big-endian
#: (network byte order). ">I" packs an int into exactly 4 bytes.
HEADER_FORMAT = ">I"

#: Size in bytes of the length prefix (struct.calcsize(">I") == 4).
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

#: Sanity cap for any single JSON metadata frame: 10 MiB. A frame that
#: claims to be larger is either a corrupted stream or a hostile peer
#: trying to make us allocate gigabytes - refuse it before allocating.
MAX_FRAME = 10 * 1024 * 1024

#: Streaming chunk size for binary file transfer: 64 KiB per read/write.
CHUNK_SIZE = 64 * 1024

# ---- Logical message types (keeps magic strings in exactly one place) ----
MSG_HELLO = "hello"           # client -> server: identify yourself
MSG_HELLO_ACK = "hello_ack"   # server -> client: identification reply
MSG_TEXT = "text"             # chat message
MSG_FILE = "file"             # phase-1 metadata of a file transfer


# ======================================================================
# SECTION 2 - EXCEPTION HIERARCHY
# ======================================================================

class ProtocolError(Exception):
    """Base class for every protocol-layer failure."""


class PeerDisconnectedError(ProtocolError):
    """The remote peer closed the socket - cleanly, or mid-frame."""


class FrameSizeError(ProtocolError):
    """A length prefix was 0 or exceeded MAX_FRAME (corrupt / hostile)."""


class MalformedMessageError(ProtocolError):
    """Payload bytes could not be decoded into a typed JSON object,
    or a message builder was given invalid fields."""


# ======================================================================
# SECTION 3 - IDENTITY & VALIDATION HELPERS
# ======================================================================

def generate_peer_id() -> str:
    """
    Return a fresh 8-character hexadecimal peer ID, e.g. 'a3f1c92e'.

    os.urandom(4) comes from the operating system's CSPRNG, so IDs are
    unpredictable and collision-free for our purposes; hex() renders
    the 4 random bytes as 8 hex characters.
    """
    return os.urandom(4).hex()


def sanitize_filename(filename: str) -> str:
    """
    Reduce any user- or wire-supplied filename to a bare, safe name.

    Why this matters (defense in depth - this is a security lab!):
    the filename arrives over the network and can NEVER be trusted.
    'C:\\Users\\Bob\\..\\..\\evil.exe' and '../../../etc/passwd' must
    not be allowed to escape the downloads/ directory. We keep only
    the final path component and reject pure relative markers.

    Raises MalformedMessageError if nothing safe remains.
    """
    # Normalise Windows-style separators so both path styles are handled.
    name = str(filename).replace("\\", "/")
    # Keep only the final path component.
    name = name.rsplit("/", 1)[-1].strip()
    if not name or name in (".", ".."):
        raise MalformedMessageError(f"Unsafe or empty filename: {filename!r}")
    return name


def _clean_name(peer_name: str) -> str:
    """Normalise a display name; blank names become 'Anonymous'."""
    cleaned = str(peer_name).strip()
    return cleaned if cleaned else "Anonymous"


def format_size(num_bytes) -> str:
    """Human-readable byte count for the UI log: '0 B', '64.0 KB', '2.3 MB'."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:,.1f} {unit}"
        size /= 1024.0


# ======================================================================
# SECTION 4 - JSON ENCODING / DECODING
# ======================================================================

def encode_message(payload: dict) -> bytes:
    """
    dict -> UTF-8 JSON bytes (no framing).

    ensure_ascii=False keeps non-ASCII characters (Bangla, emoji, etc.)
    as real UTF-8 bytes on the wire instead of \\uXXXX escapes -
    smaller payloads and human-readable packet captures.
    Raises MalformedMessageError if the dict is not JSON-serializable.
    """
    try:
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MalformedMessageError(
            f"Message is not JSON-serializable: {exc}"
        ) from exc


def decode_message(raw: bytes) -> dict:
    """
    UTF-8 JSON bytes -> dict, with structural validation:
    the payload must be a JSON *object* containing a 'type' field.
    Raises MalformedMessageError otherwise.
    """
    try:
        payload = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise MalformedMessageError(f"Payload is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise MalformedMessageError(f"Payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise MalformedMessageError(
            f"Payload must be a JSON object, got {type(payload).__name__}"
        )
    if "type" not in payload:
        raise MalformedMessageError("Payload is missing the required 'type' field")
    return payload


# ======================================================================
# SECTION 5 - LENGTH-PREFIX FRAMING (the heart of the protocol)
# ======================================================================

def frame_message(payload: dict) -> bytes:
    """
    Pure function: dict -> complete wire frame
    (4-byte big-endian length header + UTF-8 JSON body).

    Being a pure byte-in / byte-out function (no socket involved) is
    what makes the protocol unit-testable without any networking.
    """
    body = encode_message(payload)
    if len(body) > MAX_FRAME:
        raise FrameSizeError(
            f"Outgoing JSON body is {len(body):,} bytes; the metadata "
            f"frame cap is {MAX_FRAME:,} bytes"
        )
    return struct.pack(HEADER_FORMAT, len(body)) + body


def send_frame(sock, payload: dict) -> None:
    """
    Serialize, frame, and transmit one message over `sock`.

    sock.sendall() blocks until EVERY byte of the frame has been handed
    to the OS, so a frame is never half-sent (unlike sock.send(), which
    may transmit only part of the buffer and force the caller to retry).

    THREAD-SAFETY NOTE: this function does not lock. If several threads
    may write to the SAME socket, the caller must serialize sends -
    the connection pool built in Step 5 attaches one send-lock per
    peer socket for exactly this reason.

    `sock` only needs to provide .sendall(bytes): a real socket.socket
    or the in-memory _LoopbackStream used by the self-tests both work.
    """
    sock.sendall(frame_message(payload))


def recv_exact(sock, num_bytes: int) -> bytes:
    """
    Read EXACTLY `num_bytes` bytes from `sock` and return them.

    Why this function must exist: TCP gives you a byte *stream*.
    sock.recv(n) is allowed to return any count between 1 and n - the
    OS does not care about your message boundaries. Looping here
    guarantees the caller receives a complete unit (a 4-byte header or
    a full JSON body) or a clear exception, never a partial read.

    Raises:
        PeerDisconnectedError - the peer closed the connection. The
            message says whether it happened cleanly (EOF before any
            bytes of this unit) or mid-frame (partway through).
        ValueError            - num_bytes was negative.
    Socket timeouts and OS-level errors propagate unchanged so the
    node layer (Step 8) can decide how to react to them.
    """
    if num_bytes < 0:
        raise ValueError("num_bytes must be >= 0")
    if num_bytes == 0:
        return b""

    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:                                  # b"" == orderly shutdown
            received = len(buffer)
            if received:
                raise PeerDisconnectedError(
                    f"Peer disconnected mid-frame: got {received} of "
                    f"{num_bytes} expected bytes"
                )
            raise PeerDisconnectedError("Peer disconnected cleanly (EOF)")
        buffer.extend(chunk)
    return bytes(buffer)


def recv_frame(sock) -> dict:
    """
    Read one complete framed message from `sock`, return it as a dict.

    Pipeline: read exactly 4 header bytes -> unpack big-endian length
    -> sanity-check the length -> read exactly that many body bytes ->
    decode UTF-8 JSON and validate its structure.

    Raises PeerDisconnectedError if the peer goes away, FrameSizeError
    for a corrupt/hostile length prefix, MalformedMessageError for a
    broken payload. All are ProtocolError subclasses, so Step 8's
    handler can catch one family uniformly.
    """
    header = recv_exact(sock, HEADER_SIZE)
    (length,) = struct.unpack(HEADER_FORMAT, header)

    if length == 0:
        raise FrameSizeError("Rejected a zero-length frame header")
    if length > MAX_FRAME:
        raise FrameSizeError(
            f"Frame header claims {length:,} bytes, which exceeds the "
            f"{MAX_FRAME:,}-byte cap - stream is corrupt or hostile"
        )

    body = recv_exact(sock, length)
    return decode_message(body)


# ======================================================================
# SECTION 6 - TYPED MESSAGE BUILDERS (all four wire message shapes)
# ======================================================================

def build_hello(peer_id: str, peer_name: str, listen_port: int) -> dict:
    """Handshake opener, sent by the connecting side (used in Step 4)."""
    return {
        "type": MSG_HELLO,
        "peer_id": peer_id,
        "peer_name": _clean_name(peer_name),
        "port": int(listen_port),
    }


def build_hello_ack(peer_id: str, peer_name: str, listen_port: int) -> dict:
    """Handshake reply, sent by the accepting side (used in Step 4)."""
    return {
        "type": MSG_HELLO_ACK,
        "peer_id": peer_id,
        "peer_name": _clean_name(peer_name),
        "port": int(listen_port),
    }


def build_text(sender_id: str, sender_name: str, message: str) -> dict:
    """One chat message (used in Step 6). Empty text is refused."""
    text = str(message).strip()
    if not text:
        raise MalformedMessageError("Refusing to build an empty text message")
    return {
        "type": MSG_TEXT,
        "sender_id": sender_id,
        "sender_name": _clean_name(sender_name),
        "message": text,
    }


def build_file_meta(sender_id: str, sender_name: str,
                    filename: str, filesize) -> dict:
    """
    Phase-1 metadata of a file transfer (used in Step 7).
    The filename is sanitized here AND will be sanitized again by the
    receiver - never trust data that crossed the network.
    """
    size = int(filesize)
    if size < 0:
        raise MalformedMessageError("File size cannot be negative")
    return {
        "type": MSG_FILE,
        "sender_id": sender_id,
        "sender_name": _clean_name(sender_name),
        "filename": sanitize_filename(filename),
        "filesize": size,
    }


# ======================================================================
# SECTION 7 - SELF-TEST HARNESS (zero networking required)
#
#   Run:  python protocol.py
#
# A _LoopbackStream simulates a TCP connection in memory. Crucially, it
# hands out data in small fragments - exactly like real TCP does - so
# these tests prove the framing survives fragmentation, back-to-back
# messages, hostile length prefixes, and mid-frame disconnects.
# ======================================================================

class _LoopbackStream:
    """In-memory socket stand-in with deliberately fragmented recv()."""

    def __init__(self, quantum: int = 7):
        # "quantum" = max bytes one recv() call returns. 7 is odd and
        # larger than the 4-byte header but smaller than any body, which
        # forces every code path (partial header, partial body, multiple
        # loop iterations) to execute.
        self._quantum = max(1, int(quantum))
        self._inbound = bytearray()   # bytes waiting to be recv()'d

    # -- socket-compatible API consumed by send_frame / recv_frame ------
    def sendall(self, data: bytes) -> None:
        self._inbound.extend(data)

    def recv(self, bufsize: int) -> bytes:
        take = min(bufsize, self._quantum, len(self._inbound))
        piece = bytes(self._inbound[:take])
        del self._inbound[:take]
        return piece                  # b"" once drained == remote EOF

    # -- test-side helpers ------------------------------------------------
    def inject_raw(self, data: bytes) -> None:
        """Simulate arbitrary (possibly hostile) bytes arriving."""
        self._inbound.extend(data)


def _check(condition: bool, detail: str) -> None:
    """Tiny assert helper that cannot be stripped by `python -O`."""
    if not condition:
        raise AssertionError(detail)


def _test_constants() -> None:
    _check(HEADER_SIZE == 4, "length prefix must be exactly 4 bytes")
    _check(CHUNK_SIZE == 64 * 1024, "file chunk must be 64 KiB")
    # Prove big-endian byte order on the wire: 0x01020304 packs as
    # 01 02 03 04 (most significant byte first).
    _check(struct.pack(HEADER_FORMAT, 0x01020304) == b"\x01\x02\x03\x04",
           "'>I' must produce big-endian bytes")


def _test_peer_id() -> None:
    pid = generate_peer_id()
    _check(len(pid) == 8, f"peer id must be 8 hex chars, got {pid!r}")
    _check(all(c in "0123456789abcdef" for c in pid), "must be lowercase hex")
    _check(generate_peer_id() != pid, "two generated ids must differ")


def _test_roundtrip_all_types() -> None:
    # Send ALL FOUR messages back-to-back on one stream, then read all
    # four back - this is the core proof that framing preserves message
    # boundaries on a byte-stream transport.
    messages = [
        build_hello("a1b2c3d4", "Alice", 5000),
        build_hello_ack("b2c3d4e5", "Bob", 5001),
        build_text("a1b2c3d4", "Alice", "Hello Bob - framing works!"),
        build_file_meta("a1b2c3d4", "Alice", "sample.jpg", 2456789),
    ]
    stream = _LoopbackStream(quantum=7)     # fragmented like real TCP
    for msg in messages:
        send_frame(stream, msg)
    for expected in messages:
        received = recv_frame(stream)
        _check(received == expected,
               f"round trip mismatch:\n  sent: {expected}\n  got:  {received}")


def _test_byte_by_byte_stream() -> None:
    # quantum=1: the stream delivers ONE byte per recv() call - the most
    # brutal fragmentation TCP could ever produce.
    stream = _LoopbackStream(quantum=1)
    original = build_text("cafe0001", "Carol", "one byte at a time")
    send_frame(stream, original)
    _check(recv_frame(stream) == original,
           "byte-by-byte delivery broke framing")


def _test_unicode_payload() -> None:
    text = "নমস্কার! 🎉 - café"
    msg = build_text("a1b2c3d4", "Alice", text)
    wire = frame_message(msg)
    # ensure_ascii=False => the emoji travels as real UTF-8 bytes,
    # not a \\uXXXX escape sequence:
    _check("🎉".encode("utf-8") in wire, "emoji must be raw UTF-8 on the wire")
    stream = _LoopbackStream()
    stream.inject_raw(wire)
    _check(recv_frame(stream)["message"] == text, "unicode round trip failed")


def _test_filename_sanitization() -> None:
    _check(sanitize_filename("C:\\Users\\Bob\\..\\..\\evil.exe") == "evil.exe",
           "Windows path traversal must reduce to bare name")
    _check(sanitize_filename("../../../../etc/passwd") == "passwd",
           "Unix path traversal must reduce to bare name")
    _check(sanitize_filename("  photo.png  ") == "photo.png",
           "surrounding whitespace must be trimmed")
    try:
        sanitize_filename("..")
        raise AssertionError("'..' must be rejected")
    except MalformedMessageError:
        pass
    # The builder sanitizes too:
    meta = build_file_meta("a1b2c3d4", "Alice", "/home/alice/report.pdf", 1024)
    _check(meta["filename"] == "report.pdf",
           "builder must sanitize filenames")


def _test_hostile_frame_sizes() -> None:
    # A length prefix claiming more than MAX_FRAME must be refused
    # before ANY allocation happens.
    stream = _LoopbackStream()
    stream.inject_raw(struct.pack(HEADER_FORMAT, MAX_FRAME + 1))
    try:
        recv_frame(stream)
        raise AssertionError("oversized frame header was accepted")
    except FrameSizeError:
        pass

    # A zero-length header is never a legal message.
    stream2 = _LoopbackStream()
    stream2.inject_raw(struct.pack(HEADER_FORMAT, 0))
    try:
        recv_frame(stream2)
        raise AssertionError("zero-length frame was accepted")
    except FrameSizeError:
        pass


def _test_disconnects() -> None:
    # Clean EOF: nothing on the wire at all.
    stream = _LoopbackStream()
    try:
        recv_frame(stream)
        raise AssertionError("clean EOF must raise PeerDisconnectedError")
    except PeerDisconnectedError as exc:
        _check("cleanly" in str(exc), "clean EOF must be reported as clean")

    # Mid-frame EOF: header promises 100 body bytes, only 3 ever arrive.
    stream2 = _LoopbackStream()
    stream2.inject_raw(struct.pack(HEADER_FORMAT, 100) + b"abc")
    try:
        recv_frame(stream2)
        raise AssertionError("mid-frame EOF must raise PeerDisconnectedError")
    except PeerDisconnectedError as exc:
        _check("mid-frame" in str(exc), "mid-frame EOF must be flagged as such")


def _test_malformed_payloads() -> None:
    # A JSON object without a 'type' field is illegal.
    stream = _LoopbackStream()
    body = b'{"no_type": true}'
    stream.inject_raw(struct.pack(HEADER_FORMAT, len(body)) + body)
    try:
        recv_frame(stream)
        raise AssertionError("payload without 'type' must be rejected")
    except MalformedMessageError:
        pass

    # Non-object JSON (a bare list) is equally illegal.
    stream2 = _LoopbackStream()
    body2 = b"[1, 2, 3]"
    stream2.inject_raw(struct.pack(HEADER_FORMAT, len(body2)) + body2)
    try:
        recv_frame(stream2)
        raise AssertionError("non-object JSON must be rejected")
    except MalformedMessageError:
        pass


def _test_builder_validation() -> None:
    try:
        build_text("a1b2c3d4", "Alice", "   ")
        raise AssertionError("empty text message must be refused")
    except MalformedMessageError:
        pass

    try:
        build_file_meta("a1b2c3d4", "Alice", "x.bin", -5)
        raise AssertionError("negative file size must be refused")
    except MalformedMessageError:
        pass

    _check(build_hello("a1b2c3d4", "   ", 5000)["peer_name"] == "Anonymous",
           "blank display names must default to 'Anonymous'")


def _test_format_size() -> None:
    _check(format_size(0) == "0 B", "zero bytes")
    _check(format_size(512) == "512 B", "512 bytes")
    _check(format_size(64 * 1024) == "64.0 KB", "64 KiB")
    _check(format_size(2456789) == "2.3 MB", "2456789 bytes -> 2.3 MB")
    _check(format_size(1024 ** 3) == "1.0 GB", "1 GiB")


_SELF_TESTS = [
    ("wire constants & big-endian header bytes",       _test_constants),
    ("peer ID generation (8-char hex)",                _test_peer_id),
    ("round trip: all 4 message types, back-to-back",  _test_roundtrip_all_types),
    ("round trip: byte-by-byte fragmented stream",     _test_byte_by_byte_stream),
    ("unicode / emoji payload round trip",             _test_unicode_payload),
    ("filename sanitization (path traversal defense)", _test_filename_sanitization),
    ("hostile frame sizes rejected",                   _test_hostile_frame_sizes),
    ("clean & mid-frame disconnect detection",         _test_disconnects),
    ("malformed payload rejection",                    _test_malformed_payloads),
    ("message builder validation",                     _test_builder_validation),
    ("human-readable size formatting",                 _test_format_size),
]


def _run_self_test() -> int:
    print("=" * 62)
    print(" protocol.py SELF-TEST - no sockets, no threads, no GUI")
    print("=" * 62)
    passed = failed = 0
    for name, test in _SELF_TESTS:
        try:
            test()
        except Exception as exc:                     # test harness: report all
            failed += 1
            print(f"  [FAIL] {name}")
            print(f"         -> {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"  [ OK ] {name}")
    print("-" * 62)
    print(f" RESULT: {passed} passed, {failed} failed "
          f"({passed + failed} tests total)")
    print("=" * 62)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(_run_self_test())