"""
p2p_node.py
===========
The networking core of the P2P Network.

Course : CSE 433 - Blockchain & Distributed Security Lab
Author : <Your Name> - University of Asia Pacific

ROLE OF THIS MODULE
-------------------
A single P2PNode object represents ONE peer in the network and runs
BOTH sides of the P2P architecture simultaneously:

    * TCP SERVER : a bound, listening socket that accepts inbound peer
                   connections (one dedicated reader thread each).
    * TCP CLIENT : outbound connect() calls to remote peers' servers.
    * POOL       : a thread-safe connection manager keyed by peer_id,
                   enforcing ONE live link per peer. A connection only
                   enters the pool after a successful HELLO handshake.
    * MESSAGING  : send_text() engine + IncomingMessage events.
    * TRANSFER   : send_file() two-phase binary engine + IncomingFile
                   events (metadata frame, then raw 64 KiB chunks).

IMPLEMENTATION ROADMAP (built up across steps)
----------------------------------------------
    Step 3: sockets, threads, framed message loop, CLI driver
    Step 4: HELLO / HELLO_ACK handshake + peer identification gate
    Step 5: connection pool keyed by peer_id, one-live-link invariant
    Step 6: send_text() engine + IncomingMessage events
    Step 7: send_file() two-phase binary transfer engine
    Step 8 (this file, current state):
        - hardened error handling, validated by a failure gauntlet:
          hostile file metadata, mid-transfer disconnects, dead
          targets, missing files, connection floods
        - stop() now DRAINS reader threads so in-flight cleanup (like
          deleting a partial .part file) completes before process exit
        - startup sweeps stale .part debris left by hard-killed
          processes (crash recovery)

ERROR TAXONOMY - who raises, who catches
----------------------------------------
    protocol.ProtocolError family (protocol.py):
        PeerDisconnectedError  remote closed the socket (clean EOF or
                               mid-frame). Caught by reader threads ->
                               connection reaped, node lives on.
        FrameSizeError         hostile/corrupt length prefix. Caught at
                               the handshake gate AND by readers.
        MalformedMessageError  undecodable or invalid payload. Raised
                               by builders (refuse to send) and by the
                               receiver's defensive parser (refuse to
                               accept).
    HandshakeError (this module):
        Any failure during HELLO/HELLO_ACK (timeout, wrong first frame,
        invalid identity). Caught at the gate -> the connection is
        rejected before it can ever enter the pool.
    OSError family (incl. socket.timeout, WinError 10054 resets):
        Transport-level trouble anywhere, anytime. Policy: log the
        precise reason, close THAT ONE connection, keep the node and
        every other connection alive.

    GOLDEN RULE: no single connection's failure may ever take down
    the node. Every failure path ends in recovery or a clean, logged
    drop -- never a crash.

DESIGN RULE: this module never touches Tkinter widgets. All events are
reported upward through callbacks installed by main.py (Step 9); the
GUI renders them safely on the Tkinter main thread.
"""

import argparse
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass

import protocol

# ======================================================================
# SECTION 1 - TUNING CONSTANTS
# ======================================================================

#: Interface the server socket binds to. "0.0.0.0" = every interface,
#: so peers on the same LAN can reach us. Use "127.0.0.1" for
#: local-only testing (also avoids the Windows firewall prompt).
DEFAULT_HOST = "0.0.0.0"

#: Kernel backlog queue for connections awaiting accept().
LISTEN_BACKLOG = 8

#: The listening socket uses a short polling timeout so the accept loop
#: notices self.stop() within ~1s instead of blocking inside accept()
#: forever. This is the portable way to shut a TCP server down.
ACCEPT_TIMEOUT = 1.0

#: Outbound connect() timeout: fail fast if the target peer is dead.
CONNECT_TIMEOUT = 5.0

#: A new connection must complete its HELLO handshake within this many
#: seconds. Silent or stalling peers are dropped instead of parking a
#: reader thread forever.
HANDSHAKE_TIMEOUT = 5.0

#: Chat-policy limit on one text message (characters). The protocol's
#: MAX_FRAME (10 MiB) is a wire-format sanity cap; this is a sane
#: application-level limit for chat text.
MAX_TEXT_LENGTH = 8192

#: Directory where received files are stored. Anchored to THIS FILE'S
#: directory (not the CWD), so downloads land in the project's
#: downloads/ folder no matter where the app is launched from.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS_DIR = os.path.join(BASE_DIR, "downloads")

#: Anti disk-fill guard: refuse any inbound transfer larger than this.
#: A hostile peer claiming filesize=terabytes gets its connection
#: dropped instead of our disk filled.
MAX_FILE_SIZE = 1024 * 1024 * 1024          # 1 GiB

#: Progress log interval during transfers (bytes), both directions.
PROGRESS_INTERVAL = 1024 * 1024             # 1 MiB

#: Crash recovery: *.part files older than this are swept at startup.
#: The age check means we never delete a .part file that an in-flight
#: transfer (possibly from ANOTHER node sharing this downloads/ folder
#: on the same machine) is actively writing.
STALE_PART_AGE = 600              # seconds

#: How long stop() waits for each reader thread to drain, so in-flight
#: cleanup (e.g. deleting a partial .part file) finishes before the
#: process exits and daemon threads are killed.
DRAIN_TIMEOUT = 2.0               # seconds


# ======================================================================
# SECTION 2 - EVENT TYPES (public dataclasses handed to UI callbacks)
# ======================================================================

@dataclass
class IncomingMessage:
    """
    One chat message received from a peer, handed to the on_text
    callback (installed by the CLI today, the Tkinter chat window in
    Step 9). received_at is a local Unix timestamp taken the moment
    the frame was decoded -- the WIRE FORMAT itself carries no
    timestamp (the assignment spec fixes the payload fields), so
    display time is purely a local concern.
    """
    sender_id: str
    sender_name: str
    message: str
    received_at: float


@dataclass
class IncomingFile:
    """
    One file received from a peer, handed to the on_file callback
    (Step 9 GUI). `filename` is the sanitized local name it was saved
    under (after collision handling); `path` is the absolute path.
    """
    sender_id: str
    sender_name: str
    filename: str
    path: str
    size: int
    received_at: float


# ======================================================================
# SECTION 3 - HANDSHAKE ERROR, IDENTITY VALIDATION, PATH HELPERS
# ======================================================================

class HandshakeError(Exception):
    """A HELLO / HELLO_ACK handshake failed or was rejected."""


def _validate_identity(message: dict, expected_type: str):
    """
    Validate a HELLO / HELLO_ACK payload and extract the identity.

    Returns (peer_id, peer_name, port).
    Raises HandshakeError if the message is the wrong type, or any
    identity field is missing / malformed.

    NOTE: `bool` is explicitly rejected for the port because in Python
    `True` IS an instance of int -- a JSON `true` would otherwise sneak
    through the range check as port 1.
    """
    if message.get("type") != expected_type:
        raise HandshakeError(
            f"expected '{expected_type}' as first frame, "
            f"got '{message.get('type')}'")

    pid = message.get("peer_id")
    if not isinstance(pid, str) or not pid.strip():
        raise HandshakeError(f"missing or empty peer_id: {pid!r}")

    name = message.get("peer_name")
    if not isinstance(name, str) or not name.strip():
        raise HandshakeError(f"missing or empty peer_name: {name!r}")

    port = message.get("port")
    if (not isinstance(port, int) or isinstance(port, bool)
            or not 1 <= port <= 65535):
        raise HandshakeError(f"invalid advertised port: {port!r}")

    return pid.strip(), name.strip(), port


def _unique_path(directory: str, filename: str) -> str:
    """
    Return a non-clashing path inside `directory`:
    photo.jpg -> photo_1.jpg -> photo_2.jpg ... (collision handling,
    so re-receiving a file never overwrites previous evidence).
    """
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base}_{counter}{ext}")
        counter += 1
    return candidate


# ======================================================================
# SECTION 4 - PEER CONNECTION (one live TCP link to another peer)
# ======================================================================

class PeerConnection:
    """
    Wrapper around ONE connected peer socket.

    Why a wrapper instead of using raw sockets in a dict?
      * a per-socket send lock, so two threads writing at the same
        moment can never interleave two frames on the same stream -- and
        (Step 7) so an entire two-phase file transfer is indivisible;
      * identity metadata (peer_id / peer_name / advertised port),
        stamped by the HELLO handshake -- None until it completes;
      * the `replaced` flag: set when a NEWER link from the same peer
        supersedes this one, so this connection's reader thread exits
        silently instead of logging a misleading "disconnected" line;
      * a single idempotent close() used by both stop() and the
        reader-thread cleanup path.
    """

    def __init__(self, sock: socket.socket, remote_addr, inbound: bool):
        self.sock = sock
        self.remote_addr = remote_addr          # (ip, port) of the other end
        self.inbound = inbound                  # True = THEY connected to US
        self.peer_id = None                     # stamped by the handshake
        self.peer_name = None                   # stamped by the handshake
        self.peer_port = None                   # their advertised listen port
        self.replaced = False                   # True once superseded
        self._send_lock = threading.Lock()

    @property
    def endpoint(self) -> str:
        """Human-readable remote address, e.g. '127.0.0.1:5000'."""
        return f"{self.remote_addr[0]}:{self.remote_addr[1]}"

    def send_frame(self, payload: dict) -> None:
        """Thread-safe framed send of one JSON message."""
        with self._send_lock:
            protocol.send_frame(self.sock, payload)

    def send_all_bytes(self, data: bytes) -> None:
        """Thread-safe raw byte send (kept for ad-hoc raw streams)."""
        with self._send_lock:
            self.sock.sendall(data)

    def send_file_stream(self, payload: dict, path: str, progress=None) -> None:
        """
        Atomic two-phase file send: the metadata frame AND every raw
        byte of the file go out under ONE hold of the send lock.

        Why one lock hold for both phases: if another thread were
        allowed to slip a text frame between the metadata and the file
        bytes, the receiver would consume that frame's bytes as file
        content and the stream would silently corrupt. The lock makes
        the whole transfer indivisible on this socket.

        If the file shrinks below its declared size mid-transfer we
        raise, letting the caller close the socket so the RECEIVER
        errors out too, instead of blocking forever on bytes that will
        never arrive. (A file that GREW is harmless: we simply send
        exactly the declared number of bytes.)
        """
        with self._send_lock:
            protocol.send_frame(self.sock, payload)
            remaining = int(payload["filesize"])
            sent = 0
            with open(path, "rb") as fh:
                while remaining > 0:
                    chunk = fh.read(min(protocol.CHUNK_SIZE, remaining))
                    if not chunk:
                        raise OSError(
                            f"'{path}' changed size during transfer")
                    self.sock.sendall(chunk)
                    sent += len(chunk)
                    remaining -= len(chunk)
                    if progress is not None:
                        progress(sent)

    def close(self) -> None:
        """Idempotent close; safe to call from multiple threads."""
        try:
            self.sock.shutdown(socket.SHUT_RDWR)   # orderly FIN -> remote
        except OSError:                            # sees a clean EOF
            pass                                   # already dead / not connected
        finally:
            self.sock.close()                      # close() is idempotent


# ======================================================================
# SECTION 5 - THE NODE (server + client + pool + messaging + transfers)
# ======================================================================

class P2PNode:
    """One peer: TCP server, TCP client, pool, messaging, file transfer."""

    # ------------------------------------------------------------------
    # Construction & lifecycle
    # ------------------------------------------------------------------

    def __init__(self, peer_name, host=DEFAULT_HOST, port=5000):
        self.peer_id = protocol.generate_peer_id()
        self.peer_name = str(peer_name).strip() or "Anonymous"
        self.host = str(host)
        try:
            self.port = int(port)
        except (TypeError, ValueError):
            raise ValueError(f"Invalid port: {port!r}") from None
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Port {self.port} out of range 1-65535")

        # ---- runtime state (guarded by self._lock) ----
        self._running = False
        self._server_sock = None
        self._accept_thread = None
        # POOL: peer_id -> PeerConnection.
        # INVARIANT: exactly zero or one live link per peer_id.
        self._connections = {}
        self._lock = threading.Lock()
        self._log_lock = threading.Lock()
        self._log_hook = None       # installed by the GUI in Step 9
        self._on_text = None        # installed by the CLI today, GUI in Step 9
        self._on_file = None        # installed by the GUI in Step 9
        # Reader threads currently alive; stop() drains them so
        # in-flight cleanup finishes before process exit.
        self._readers = set()

        # Ensure the downloads folder exists up front (also for the GUI).
        os.makedirs(DOWNLOADS_DIR, exist_ok=True)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def connection_count(self) -> int:
        with self._lock:
            return len(self._connections)

    def start(self) -> None:
        """
        Bring up the TCP server: socket -> SO_REUSEADDR -> bind ->
        listen -> dedicated accept-loop thread. Also performs crash
        recovery: stale .part debris from hard-killed processes is
        swept from downloads/ before new work is accepted.
        """
        if self._running:
            self._log("WARN", "Peer is already running")
            return

        self._sweep_stale_parts()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # SO_REUSEADDR: allows rebinding right after an unclean exit,
            # while the old socket sits in TIME_WAIT.
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(LISTEN_BACKLOG)
            # Polling timeout so the accept loop can notice stop().
            srv.settimeout(ACCEPT_TIMEOUT)
        except OSError as exc:
            srv.close()
            self._log("ERROR", f"Cannot listen on {self.host}:{self.port} - {exc}")
            raise

        self._server_sock = srv
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"accept-{self.peer_id}",
            daemon=True,
        )
        self._accept_thread.start()
        self._log("INFO",
                  f"Peer '{self.peer_name}' ({self.peer_id}) "
                  f"listening on {self.host}:{self.port}")

    def stop(self) -> None:
        """
        Idempotent, thread-safe shutdown of the server and every live
        connection. Safe to call from the CLI, the GUI, or a callback.

        DRAIN PHASE: after the sockets are closed, reader threads get a
        short grace window to finish in-flight cleanup (e.g. deleting a
        partial .part file after an interrupted transfer) before the
        process exits and daemon threads are killed mid-work.
        """
        with self._lock:
            if not self._running:
                return
            self._running = False
            conns = list(self._connections.values())
            self._connections.clear()
            srv = self._server_sock
            self._server_sock = None

        # Closing the listening socket plus the flag makes the accept
        # loop exit quietly (it will not log a crash for our own stop).
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass

        # Closing each peer socket unblocks its reader thread; readers
        # see _running == False and exit silently.
        for conn in conns:
            conn.close()

        if (self._accept_thread is not None
                and self._accept_thread is not threading.current_thread()):
            self._accept_thread.join(timeout=2.0)
        self._accept_thread = None

        # DRAIN: wait briefly for each reader to finish its cleanup.
        with self._lock:
            readers = [t for t in self._readers
                       if t is not threading.current_thread() and t.is_alive()]
        for thread in readers:
            thread.join(timeout=DRAIN_TIMEOUT)

        self._log("INFO", f"Peer stopped - {len(conns)} connection(s) closed")

    def _sweep_stale_parts(self) -> None:
        """
        Crash recovery: delete leftover *.part files from transfers
        interrupted by a hard process kill (where no cleanup could run).
        Only files older than STALE_PART_AGE are swept, so a .part file
        being actively written -- possibly by ANOTHER node sharing this
        downloads/ folder on the same machine -- is never disturbed.
        """
        try:
            now = time.time()
            swept = 0
            for name in os.listdir(DOWNLOADS_DIR):
                if not name.endswith(".part"):
                    continue
                path = os.path.join(DOWNLOADS_DIR, name)
                try:
                    if now - os.path.getmtime(path) > STALE_PART_AGE:
                        os.remove(path)
                        swept += 1
                except OSError:
                    pass            # raced away or locked by another process
            if swept:
                self._log("INFO",
                          f"Crash recovery: swept {swept} stale .part "
                          f"file(s) from interrupted transfers")
        except FileNotFoundError:
            pass                    # downloads/ not created yet (defensive)

    def _spawn_reader(self, conn: PeerConnection) -> None:
        """
        Start the dedicated reader thread for `conn` and register it in
        the drain set, so stop() can wait for in-flight work (such as a
        .part cleanup mid-transfer) before the process exits.
        """
        thread = threading.Thread(
            target=self._handle_connection,
            args=(conn,),
            name=f"reader-{conn.endpoint}",
            daemon=True,
        )
        with self._lock:
            self._readers.add(thread)
        thread.start()

    # ------------------------------------------------------------------
    # Event bridges (console/CLI today, GUI in Step 9)
    # ------------------------------------------------------------------

    def set_log_callback(self, callback) -> None:
        """
        Install `callback(level: str, message: str)` to receive every
        event. It is called from NETWORK THREADS, so it must be fast,
        non-blocking, and must never touch Tkinter widgets directly
        (main.py will bridge into the GUI via a queue in Step 9).
        """
        self._log_hook = callback

    def set_on_text_callback(self, callback) -> None:
        """
        Install `callback(IncomingMessage)` to receive every incoming
        chat message as a STRUCTURED event. Same threading rules as the
        log callback. With no callback installed, text messages fall
        back to a CHAT line in the log.
        """
        self._on_text = callback

    def set_on_file_callback(self, callback) -> None:
        """
        Install `callback(IncomingFile)` to receive every completed
        inbound file transfer as a STRUCTURED event (Step 9 GUI).
        The INFO log lines are always emitted regardless.
        """
        self._on_file = callback

    def _log(self, level: str, message: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] [{level:>5}] {message}"
        with self._log_lock:
            if self._log_hook is not None:
                try:
                    self._log_hook(level, message)
                except Exception:
                    # A broken GUI hook must never kill a network thread.
                    print(line, flush=True)
            else:
                print(line, flush=True)

    # ------------------------------------------------------------------
    # HELLO / HELLO_ACK handshake (Step 4)
    # ------------------------------------------------------------------

    def _handshake_as_client(self, conn: PeerConnection):
        """
        Initiator side: send HELLO, demand a valid HELLO_ACK back.
        Returns the remote identity tuple (peer_id, peer_name, port).
        Raises HandshakeError on timeout, malformed identity, or
        connection trouble - the caller must then drop the connection.
        """
        try:
            conn.sock.settimeout(HANDSHAKE_TIMEOUT)
            conn.send_frame(
                protocol.build_hello(self.peer_id, self.peer_name, self.port))
            ack = protocol.recv_frame(conn.sock)
            identity = _validate_identity(ack, protocol.MSG_HELLO_ACK)
        except HandshakeError:
            raise
        except socket.timeout:
            raise HandshakeError(
                f"no HELLO_ACK within {HANDSHAKE_TIMEOUT:.0f}s") from None
        except protocol.ProtocolError as exc:
            raise HandshakeError(
                f"protocol violation during handshake: {exc}") from exc
        except OSError as exc:
            raise HandshakeError(
                f"connection error during handshake: {exc}") from exc

        conn.sock.settimeout(None)   # fully blocking for the message loop
        return identity

    def _handshake_as_server(self, conn: PeerConnection):
        """
        Acceptor side: demand a valid HELLO as the very first frame,
        answer with HELLO_ACK. Returns the remote identity tuple.
        Raises HandshakeError on any failure.
        """
        try:
            conn.sock.settimeout(HANDSHAKE_TIMEOUT)
            hello = protocol.recv_frame(conn.sock)
            identity = _validate_identity(hello, protocol.MSG_HELLO)
            conn.send_frame(
                protocol.build_hello_ack(self.peer_id, self.peer_name, self.port))
        except HandshakeError:
            raise
        except socket.timeout:
            raise HandshakeError(
                f"no HELLO within {HANDSHAKE_TIMEOUT:.0f}s") from None
        except protocol.ProtocolError as exc:
            raise HandshakeError(
                f"protocol violation during handshake: {exc}") from exc
        except OSError as exc:
            raise HandshakeError(
                f"connection error during handshake: {exc}") from exc

        conn.sock.settimeout(None)   # fully blocking for the message loop
        return identity

    # ------------------------------------------------------------------
    # THE POOL (Step 5): one live link per peer_id
    # ------------------------------------------------------------------

    def _register_connection(self, conn: PeerConnection) -> None:
        """
        Add an IDENTIFIED connection to the pool, enforcing the
        ONE-LIVE-LINK-PER-PEER rule.

        If this peer_id already has a connection, the NEWEST handshake
        wins and the older link is closed. Rationale: after a crash +
        reconnect, the old socket is a dead half-open TCP link -- the
        fresh connection is the truth. It also guarantees exactly-once
        delivery per peer for broadcasts (no duplicate links = no
        double-sends into a black hole).
        """
        replaced = None
        with self._lock:
            existing = self._connections.get(conn.peer_id)
            if existing is not conn:
                self._connections[conn.peer_id] = conn
                replaced = existing

        if replaced is not None:
            replaced.replaced = True     # its reader exits silently
            self._log("INFO",
                      f"Duplicate link from '{conn.peer_name}' "
                      f"({conn.peer_id}) - closing the older connection, "
                      f"newest wins")
            # Closing the loser unblocks its reader thread; the identity
            # check in _remove_connection stops that stale reader from
            # evicting the fresh connection that replaced it.
            replaced.close()

    def _remove_connection(self, conn: PeerConnection) -> None:
        """
        Cleanup path for reader threads.

        CRITICAL CONCURRENCY RULE: only evict the registry entry if it
        still points at THIS connection object (`is`, not key equality).
        A stale reader - e.g. the loser of a duplicate replacement - must
        never evict the fresh connection that took its place.
        """
        with self._lock:
            if self._connections.get(conn.peer_id) is conn:
                del self._connections[conn.peer_id]
        conn.close()

    # ------------------------------------------------------------------
    # Server side: accept loop
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        """
        Dedicated thread: accept inbound peers and hand each one to a
        reader thread. NOTE: no registry entry is created here - the
        reader thread registers the connection only after the HELLO
        handshake succeeds (see _handle_connection).
        """
        while self._running:
            try:
                sock, addr = self._server_sock.accept()
            except socket.timeout:
                continue                       # poll the flag again
            except OSError:
                if self._running:              # not caused by our own stop()
                    self._log("ERROR", "Accept loop crashed - server halted")
                break

            conn = PeerConnection(sock, addr, inbound=True)
            self._spawn_reader(conn)
            self._log("INFO",
                      f"Inbound connection from {conn.endpoint} - awaiting HELLO")

    # ------------------------------------------------------------------
    # Client side: outbound connections
    # ------------------------------------------------------------------

    def connect_peer(self, host, port) -> PeerConnection:
        """
        Dial another peer's server and complete the HELLO handshake
        SYNCHRONOUSLY, so the caller learns immediately whether the
        peer was reached and identified. Returns the identified
        PeerConnection. All failures are logged here and then raised.
        """
        if not self._running:
            raise RuntimeError("Peer is not running - call start() first")

        try:
            port = int(port)
        except (TypeError, ValueError):
            self._log("ERROR", f"Invalid target port: {port!r}")
            raise ValueError(f"Invalid port: {port!r}") from None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(CONNECT_TIMEOUT)   # fail fast on dead targets
            sock.connect((str(host).strip(), port))
        except OSError as exc:
            sock.close()
            self._log("ERROR", f"connect to {host}:{port} failed - {exc}")
            raise

        conn = PeerConnection(sock, sock.getpeername(), inbound=False)
        try:
            (conn.peer_id,
             conn.peer_name,
             conn.peer_port) = self._handshake_as_client(conn)
        except HandshakeError as exc:
            conn.close()
            self._log("ERROR",
                      f"Handshake with {host}:{port} rejected - {exc}")
            raise

        # Pool entry: one live link per peer_id. If we were already
        # connected to this peer, the newest handshake replaces the
        # older (possibly dead) link.
        self._register_connection(conn)

        self._spawn_reader(conn)
        self._log("INFO",
                  f"Connected to peer '{conn.peer_name}' ({conn.peer_id}) "
                  f"-> {conn.endpoint} [listening on port {conn.peer_port}]")
        return conn

    # ------------------------------------------------------------------
    # Reader threads: handshake gate + one loop per connection
    # ------------------------------------------------------------------

    def _handle_connection(self, conn: PeerConnection) -> None:
        """
        Dedicated reader thread for one peer socket.

        INBOUND connections must first pass the handshake gate: the
        first frame has to be a valid HELLO, answered with HELLO_ACK.
        Only then is the connection registered in the pool and promoted
        to the message loop. OUTBOUND connections were already
        handshaked synchronously inside connect_peer().
        """
        try:
            if not self._running:
                return

            if conn.inbound:
                try:
                    (conn.peer_id,
                     conn.peer_name,
                     conn.peer_port) = self._handshake_as_server(conn)
                except HandshakeError as exc:
                    # GATE: unidentified or malformed connections never
                    # reach the message loop or the registry.
                    self._log("ERROR", f"Rejected {conn.endpoint} - {exc}")
                    return

                if not self._running:          # stopped mid-handshake
                    return
                self._register_connection(conn)
                self._log("INFO",
                          f"Peer '{conn.peer_name}' ({conn.peer_id}) "
                          f"joined <- {conn.endpoint} "
                          f"[listening on port {conn.peer_port}]")

            while self._running:
                try:
                    message = protocol.recv_frame(conn.sock)
                except protocol.PeerDisconnectedError as exc:
                    if self._running and not conn.replaced:
                        self._log("INFO",
                                  f"'{conn.peer_name or conn.endpoint}' "
                                  f"disconnected - {exc}")
                    break
                except (protocol.ProtocolError, OSError) as exc:
                    # Connection reset / aborted, or a frame that violates
                    # the protocol: drop the connection, keep the node alive.
                    if self._running and not conn.replaced:
                        self._log("ERROR",
                                  f"Dropping "
                                  f"'{conn.peer_name or conn.endpoint}' - {exc}")
                    break
                # _dispatch returns False when it had to drop the
                # connection itself (e.g. rejected file metadata).
                if not self._dispatch(conn, message):
                    break
        finally:
            self._remove_connection(conn)
            # Deregister this thread from the drain set.
            with self._lock:
                self._readers.discard(threading.current_thread())

    def _dispatch(self, conn: PeerConnection, message: dict) -> bool:
        """
        Route one decoded message.
        Returns True if the connection is still healthy; False means
        _dispatch had to drop it (the reader loop then exits).
        """
        mtype = message.get("type")

        if mtype == protocol.MSG_TEXT:
            # ---- Defensive parsing: never trust fields that crossed
            # ---- the wire, even from a peer that passed the handshake.
            text = message.get("message")
            if not isinstance(text, str) or not text.strip():
                self._log("ERROR",
                          f"Malformed text message from "
                          f"'{conn.peer_name or conn.endpoint}' - ignored")
                return True
            sender_name = message.get("sender_name")
            if not isinstance(sender_name, str) or not sender_name.strip():
                sender_name = "unknown"
            sender_id = message.get("sender_id")
            if not isinstance(sender_id, str) or not sender_id.strip():
                sender_id = "?"

            event = IncomingMessage(
                sender_id=sender_id,
                sender_name=sender_name,
                message=text,
                received_at=time.time(),
            )

            if self._on_text is not None:
                try:
                    self._on_text(event)
                except Exception:
                    # A broken UI hook must never kill a reader thread;
                    # fall back to the log line so the message is not lost.
                    self._log("CHAT", f"{sender_name}> {text}")
            else:
                self._log("CHAT", f"{sender_name}> {text}")
            return True

        if mtype == protocol.MSG_FILE:
            return self._receive_file(conn, message)

        self._log("INFO",
                  f"Got '{mtype}' frame from "
                  f"'{conn.peer_name or conn.endpoint}' - ignored")
        return True

    # ------------------------------------------------------------------
    # FILE TRANSFER ENGINE (Step 7): two-phase, 64 KiB chunks
    # ------------------------------------------------------------------

    def _receive_file(self, conn: PeerConnection, message: dict) -> bool:
        """
        Phase-2 receiver: consume exactly `filesize` raw bytes and store
        them under downloads/ (writing to a .part file first, renamed
        only on success, so a half-finished transfer never masquerades
        as a complete file).

        Returns True if the connection is still protocol-synchronized
        afterwards; False means the connection was dropped (rejected
        metadata, oversized file, or a mid-transfer failure).
        """
        sender_name = message.get("sender_name")
        if not isinstance(sender_name, str) or not sender_name.strip():
            sender_name = "unknown"
        sender_id = message.get("sender_id")
        if not isinstance(sender_id, str) or not sender_id.strip():
            sender_id = "?"

        # --- metadata validation: NEVER trust the wire ----------------
        # (The sender sanitized the filename at build time, but a
        # modified client can still send '../../evil.exe'.)
        try:
            safe_name = protocol.sanitize_filename(message.get("filename"))
        except protocol.MalformedMessageError as exc:
            self._log("ERROR",
                      f"Rejected file from "
                      f"'{conn.peer_name or conn.endpoint}' - {exc}; "
                      f"dropping connection")
            conn.close()
            return False

        size = message.get("filesize")
        if (not isinstance(size, int) or isinstance(size, bool)
                or size < 0 or size > MAX_FILE_SIZE):
            self._log("ERROR",
                      f"Rejected file '{safe_name}' from "
                      f"'{conn.peer_name or conn.endpoint}' - invalid or "
                      f"oversized size ({size!r}, cap "
                      f"{protocol.format_size(MAX_FILE_SIZE)}); "
                      f"dropping connection")
            conn.close()
            return False

        os.makedirs(DOWNLOADS_DIR, exist_ok=True)
        final_path = _unique_path(DOWNLOADS_DIR, safe_name)
        temp_path = final_path + ".part"
        saved_name = os.path.basename(final_path)

        self._log("INFO",
                  f"'{conn.peer_name}' is sending '{safe_name}' "
                  f"({protocol.format_size(size)}) ...")

        received = 0
        next_report = PROGRESS_INTERVAL
        try:
            with open(temp_path, "wb") as fh:
                remaining = size
                while remaining > 0:
                    chunk = protocol.recv_exact(
                        conn.sock, min(protocol.CHUNK_SIZE, remaining))
                    fh.write(chunk)
                    remaining -= len(chunk)
                    received += len(chunk)
                    if received >= next_report and remaining > 0:
                        pct = (received * 100) // size
                        self._log("INFO",
                                  f"Receiving '{safe_name}': "
                                  f"{protocol.format_size(received)} / "
                                  f"{protocol.format_size(size)} ({pct}%)")
                        next_report = received + PROGRESS_INTERVAL
            os.replace(temp_path, final_path)   # atomic completion
        except (protocol.PeerDisconnectedError, protocol.ProtocolError,
                OSError) as exc:
            self._log("ERROR",
                      f"Transfer of '{safe_name}' from "
                      f"'{conn.peer_name or conn.endpoint}' failed after "
                      f"{protocol.format_size(received)} - {exc}")
            try:
                os.remove(temp_path)            # never leave partial files
            except OSError:
                pass
            conn.close()                        # stream unusable: drop it
            return False

        self._log("INFO",
                  f"Saved '{saved_name}' ({protocol.format_size(size)}) "
                  f"from '{conn.peer_name}' -> {final_path}")

        event = IncomingFile(
            sender_id=sender_id,
            sender_name=sender_name,
            filename=saved_name,
            path=final_path,
            size=size,
            received_at=time.time(),
        )
        if self._on_file is not None:
            try:
                self._on_file(event)
            except Exception:
                # A broken UI hook must never kill a reader thread.
                pass
        return True

    def send_file(self, path, target=None) -> int:
        """
        THE file transfer engine (the Step 9 GUI's 'Choose File & Send'
        button calls exactly this).

            target=None              -> send to every connected peer
            target="Bob" / peer_id   -> send to that one peer

        Phase 1: one framed JSON metadata message.
        Phase 2: exactly `filesize` raw bytes streamed in 64 KiB chunks
                 -- the whole transfer holds the per-socket send lock so
                 no other frame can interleave (see
                 PeerConnection.send_file_stream).

        Returns the number of peers the file was delivered to.
        Raises FileNotFoundError if the local file does not exist.
        """
        path = str(path).strip().strip('"')
        if not os.path.isfile(path):
            self._log("ERROR", f"File not found: {path}")
            raise FileNotFoundError(path)

        filename = os.path.basename(path)
        size = os.path.getsize(path)
        meta = protocol.build_file_meta(self.peer_id, self.peer_name,
                                        filename, size)

        if target is None:
            with self._lock:
                conns = list(self._connections.values())
            if not conns:
                self._log("WARN", "Nobody is connected - file not sent.")
                return 0
        else:
            target_conn = self.find_peer(target)
            if target_conn is None:
                self._log("WARN",
                          f"Cannot send - no connected peer matches '{target}'")
                return 0
            conns = [target_conn]

        delivered = 0
        for conn in conns:
            label = conn.peer_name or conn.endpoint
            self._log("INFO",
                      f"Sending '{meta['filename']}' "
                      f"({protocol.format_size(size)}) -> '{label}'")
            progress = self._transfer_progress_logger(meta["filename"],
                                                      label, size)
            try:
                conn.send_file_stream(meta, path, progress=progress)
            except OSError as exc:
                self._log("ERROR",
                          f"Transfer of '{meta['filename']}' to '{label}' "
                          f"failed - {exc}")
                # The byte stream is poisoned mid-transfer; close the
                # socket so both sides reap the connection cleanly.
                conn.close()
                continue
            delivered += 1
            self._log("INFO",
                      f"File '{meta['filename']}' "
                      f"({protocol.format_size(size)}) delivered to '{label}'")
        return delivered

    def _transfer_progress_logger(self, filename, peer_label, total):
        """
        Build a progress callback that logs at most every
        PROGRESS_INTERVAL bytes (a 2 GB transfer must not spam one line
        per 64 KiB chunk).
        """
        state = {"next": PROGRESS_INTERVAL}

        def report(sent: int) -> None:
            if sent >= state["next"]:
                pct = (sent * 100) // total if total else 100
                self._log("INFO",
                          f"'{filename}' -> '{peer_label}': "
                          f"{protocol.format_size(sent)} / "
                          f"{protocol.format_size(total)} ({pct}%)")
                state["next"] = sent + PROGRESS_INTERVAL

        return report

    # ------------------------------------------------------------------
    # Text engine (Step 6) + low-level sends
    # ------------------------------------------------------------------

    def send_text(self, message, target=None) -> int:
        """
        THE messaging engine entry point (the Step 9 GUI's Send button
        calls exactly this).

            target=None              -> broadcast to every connected peer
            target="Bob" / peer_id   -> private message to that one peer

        Returns the number of peers the message was delivered to.
        Raises protocol.MalformedMessageError for empty or oversized
        text; logs a WARN itself when there is nobody to receive.

        OWN-ECHO DISCIPLINE: the sender does NOT receive its own
        message back from the network (the protocol has no echo
        server). Every UI renders its own outgoing messages locally -
        instant, authoritative, and zero extra traffic.
        """
        text = str(message)
        if len(text) > MAX_TEXT_LENGTH:
            raise protocol.MalformedMessageError(
                f"Message too long: {len(text):,} chars "
                f"(limit {MAX_TEXT_LENGTH:,})")

        payload = protocol.build_text(self.peer_id, self.peer_name, text)

        if target is None:
            delivered = self.send_frame_to_all(payload)
            if delivered == 0:
                self._log("WARN", "Nobody is connected - message not sent.")
            return delivered

        conn = self.find_peer(target)
        if conn is None:
            self._log("WARN",
                      f"Cannot send - no connected peer matches '{target}'")
            return 0
        return 1 if self.send_to_peer(conn.peer_id, payload) else 0

    def send_frame_to_all(self, payload: dict) -> int:
        """
        Broadcast one framed message to every live peer in the pool.
        Returns the number of peers actually reached.
        Snapshot first, send after: never hold the pool lock across
        blocking network I/O.
        """
        with self._lock:
            conns = list(self._connections.values())
        sent = 0
        for conn in conns:
            try:
                conn.send_frame(payload)
                sent += 1
            except OSError as exc:
                self._log("ERROR",
                          f"Send to '{conn.peer_name or conn.endpoint}' "
                          f"failed - {exc}")
        return sent

    def send_to_peer(self, peer_id: str, payload: dict) -> bool:
        """
        Send one framed message to ONE specific identified peer.
        Returns True if the peer was found and the bytes went out.
        (Same discipline as the broadcast: snapshot under the lock,
        send outside it.)
        """
        with self._lock:
            conn = self._connections.get(peer_id)
        if conn is None:
            return False
        try:
            conn.send_frame(payload)
            return True
        except OSError as exc:
            self._log("ERROR",
                      f"Send to '{conn.peer_name}' ({peer_id}) failed - {exc}")
            return False

    # ------------------------------------------------------------------
    # Peer lookup & roster (used by the CLI now, the GUI in Step 9)
    # ------------------------------------------------------------------

    def find_peer(self, name_or_id):
        """
        Resolve a connected peer by exact peer_id or case-insensitive
        display name. Returns the PeerConnection, or None if no live
        peer matches.
        """
        key = str(name_or_id).strip()
        if not key:
            return None
        lowered = key.lower()
        with self._lock:
            for conn in self._connections.values():
                if conn.peer_id == key or (conn.peer_name or "").lower() == lowered:
                    return conn
        return None

    def get_peer_summaries(self):
        """
        Thread-safe roster for UI display. The Step 9 GUI polls this
        to refresh its 'Connected Peers' list. Returns a list of dicts.
        """
        with self._lock:
            return [
                {
                    "peer_id": c.peer_id,
                    "peer_name": c.peer_name or "unknown",
                    "endpoint": c.endpoint,
                    "inbound": c.inbound,
                    "listen_port": c.peer_port,
                }
                for c in self._connections.values()
            ]

    def get_connections(self):
        """Thread-safe snapshot of live PeerConnection objects."""
        with self._lock:
            return list(self._connections.values())


# ======================================================================
# SECTION 6 - CLI SMOKE-TEST DRIVER (used until the GUI arrives in Step 9)
#
#   Terminal 1:  python p2p_node.py --name Alice --port 5000
#   Terminal 2:  python p2p_node.py --name Bob --port 5001 --connect 127.0.0.1:5000
#   Terminal 3:  python p2p_node.py --name Carol --port 5002 \
#                  --connect 127.0.0.1:5000 --connect 127.0.0.1:5001
# ======================================================================

def _run_cli() -> int:
    parser = argparse.ArgumentParser(
        description="P2P node - terminal smoke-test driver (CSE 433 lab)")
    parser.add_argument("--name", default="Peer",
                        help="display name (default: Peer)")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"bind address (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=5000,
                        help="listening port (default: 5000)")
    parser.add_argument("--connect", action="append", default=[],
                        metavar="IP:PORT",
                        help="connect to a remote peer at startup (repeatable)")
    args = parser.parse_args()

    node = P2PNode(args.name, host=args.host, port=args.port)

    # ---- Console sinks (interleaving-proof) ----------------------------
    # Network threads log asynchronously while the main thread may be
    # blocked inside input(). While input is pending, every line is
    # pushed onto its own fresh row and the "> " prompt is redrawn
    # after it. Keystrokes live in the console input buffer, so the
    # submitted text is ALWAYS correct -- this is purely cosmetic.
    reading_input = False

    def _console_log(level: str, message: str) -> None:
        nonlocal reading_input
        line = f"[{time.strftime('%H:%M:%S')}] [{level:>5}] {message}"
        if reading_input:
            print(f"\n{line}\n> ", end="", flush=True)
        else:
            print(line, flush=True)

    node.set_log_callback(_console_log)

    # Incoming chat rides the SAME printer via the structured hook -
    # this is exactly how the Step 9 GUI will consume chat events.
    def _on_text(msg: IncomingMessage) -> None:
        _console_log("CHAT", f"{msg.sender_name}> {msg.message}")

    node.set_on_text_callback(_on_text)

    try:
        node.start()
    except OSError as exc:
        print(f"[fatal] could not start peer: {exc}", file=sys.stderr)
        return 1

    for target in args.connect:
        host, _, port = target.partition(":")
        try:
            node.connect_peer(host, port)
        except (OSError, ValueError, HandshakeError):
            # connect_peer already logged the precise reason; keep the
            # driver alive so one bad target doesn't kill the rest.
            continue

    node._log("INFO", "Type a line to send to all connected peers. "
                      "Commands: /list, /msg <peer> <text>, "
                      "/file <path>, /fileto <peer> <path>, /quit")
    try:
        while True:
            reading_input = True
            try:
                line = input("> ")
            except EOFError:
                break
            finally:
                reading_input = False

            cmd = line.strip()
            if not cmd:
                continue
            low = cmd.lower()
            if low in ("/quit", "/exit", "quit", "exit"):
                break
            if low == "/list":
                peers = node.get_peer_summaries()
                if not peers:
                    node._log("INFO", "No live connections.")
                for i, p in enumerate(peers, 1):
                    arrow = "<-in " if p["inbound"] else "out->"
                    node._log("INFO",
                              f"  {i}. {arrow} {p['peer_name']} "
                              f"({p['peer_id']}) @ {p['endpoint']} "
                              f"[listens on {p['listen_port']}]")
                continue
            if low == "/msg" or low.startswith("/msg "):
                parts = cmd.split(None, 2)      # ['/msg', '<peer>', '<text>']
                if len(parts) < 3:
                    node._log("WARN",
                              "Usage: /msg <peer-name-or-id> <message>")
                    continue
                _, target_name, text = parts
                try:
                    delivered = node.send_text(text, target=target_name)
                except protocol.ProtocolError as exc:
                    node._log("ERROR", f"Message rejected - {exc}")
                    continue
                if delivered:
                    # Own-echo: the sender renders its own private line
                    # locally (the network never sends it back).
                    node._log("SENT", f"you-> {target_name}: {text}")
                continue
            if low == "/fileto" or low.startswith("/fileto "):
                # NOTE: /fileto must be checked BEFORE /file.
                parts = cmd.split(None, 2)      # ['/fileto', '<peer>', '<path>']
                if len(parts) < 3:
                    node._log("WARN",
                              "Usage: /fileto <peer-name-or-id> <path>")
                    continue
                _, target_name, path = parts
                try:
                    node.send_file(path.strip().strip('"'),
                                   target=target_name)
                except (OSError, protocol.ProtocolError):
                    # send_file already logged the precise reason.
                    continue
                continue
            if low == "/file" or low.startswith("/file "):
                path = cmd[5:].strip().strip('"')   # tolerate quoted paths
                if not path:
                    node._log("WARN", "Usage: /file <path-to-file>")
                    continue
                try:
                    node.send_file(path)             # broadcast to all
                except (OSError, protocol.ProtocolError):
                    continue
                continue
            try:
                delivered = node.send_text(cmd)             # broadcast
            except protocol.ProtocolError as exc:
                node._log("ERROR", f"Message rejected - {exc}")
                continue
            if delivered:
                # Own-echo for broadcasts (zero-delivery WARN already
                # emitted by send_text itself).
                node._log("SENT", f"you> {cmd}")
    except KeyboardInterrupt:
        print()
    finally:
        node.stop()
    return 0


if __name__ == "__main__":
    sys.exit(_run_cli())