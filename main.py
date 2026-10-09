"""
main.py
=======
Entry point and graphical front-end of the P2P Network.

Course : CSE 433 - Blockchain & Distributed Security Lab
Author : <Your Name> - University of Asia Pacific

ROLE OF THIS MODULE
-------------------
Builds the complete Tkinter interface:

    * Local peer controls     (name, port, Start / Stop)
    * Remote connect controls (target IP, target port, Connect)
    * Connected peers list    (live view of the pool; select one peer
                              to send privately, or leave unselected
                              to broadcast to everyone)
    * Message input + Send
    * "Choose File & Send"    (binary transfer trigger)
    * Color-coded, scrollable message / event log

and wires every widget to the P2PNode core in p2p_node.py.

THREADING MODEL (the most important design rule in this file)
-------------------------------------------------------------
Tkinter widgets may ONLY be modified from the main thread. Network
threads therefore never touch the GUI: the node's three callbacks
(log / on_text / on_file) run on reader threads and simply push events
into a thread-safe queue.Queue. A root.after() poller drains that
queue on the Tkinter main thread and renders the events:

    reader threads ---> callbacks ---> queue.Queue ---> root.after()
    (network side)      (put, fast)    (thread-safe)   poller renders

Slow operations (connect_peer, send_file) run in short-lived worker
threads so the window never freezes.

Run this file to launch the application:  python main.py
"""

import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

import p2p_node
import protocol

# ----------------------------------------------------------------------
# Tuning constants
# ----------------------------------------------------------------------

#: How often the GUI drains the event queue (ms). 100 ms feels instant
#: to a human while keeping the Tkinter main loop light.
POLL_MS = 100

#: How often the Connected Peers list is rebuilt from the node pool (ms).
PEERS_POLL_MS = 500

#: Log colours per level tag.
LOG_COLORS = {
    "INFO":  "#333333",   # neutral gray
    "CHAT":  "#0b5394",   # blue    - incoming chat
    "SENT":  "#38761d",   # green   - your own outgoing messages
    "WARN":  "#b45f06",   # orange  - recoverable problems
    "ERROR": "#cc0000",   # red     - failures / hostile input
    "FILE":  "#674ea7",   # purple  - completed file transfers
}


class P2PGui:
    """Tkinter front-end bound to one P2PNode backend."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.node = None                    # created when Start is pressed
        self.events = queue.Queue()         # network threads -> GUI thread
        self._peer_rows = []                # listbox index -> (peer_id, name)

        self._build_ui()
        self._apply_state(started=False)

        # Long-running pollers (each reschedules itself forever).
        self.root.after(POLL_MS, self._drain_events)
        self.root.after(PEERS_POLL_MS, self._refresh_peers)

        # Clean shutdown on the window's X button.
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ==================================================================
    # UI construction
    # ==================================================================

    def _build_ui(self):
        self.root.title("P2P Network - CSE 433 Lab (serverless, TCP)")
        self.root.minsize(880, 620)

        # ---- Top row: local peer | remote connect | peers list --------
        top = ttk.Frame(self.root, padding=(8, 4))
        top.pack(fill=tk.X)

        # -- Local peer controls --
        local = ttk.LabelFrame(top, text="Local Peer", padding=8)
        local.pack(side=tk.LEFT, fill=tk.BOTH)
        ttk.Label(local, text="Name:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.name_var = tk.StringVar(value="Peer")
        self.name_entry = ttk.Entry(local, textvariable=self.name_var, width=12)
        self.name_entry.grid(row=0, column=1, padx=4)
        ttk.Label(local, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.port_var = tk.StringVar(value="5000")
        self.port_entry = ttk.Entry(local, textvariable=self.port_var, width=12)
        self.port_entry.grid(row=1, column=1, padx=4)
        self.start_btn = ttk.Button(local, text="Start Peer",
                                    command=self._start_peer)
        self.start_btn.grid(row=0, column=2, padx=(10, 0), sticky=tk.EW)
        self.stop_btn = ttk.Button(local, text="Stop Peer",
                                   command=self._stop_peer)
        self.stop_btn.grid(row=1, column=2, padx=(10, 0), sticky=tk.EW)

        # -- Remote connect controls --
        remote = ttk.LabelFrame(top, text="Connect to Remote Peer", padding=8)
        remote.pack(side=tk.LEFT, fill=tk.BOTH, padx=8)
        ttk.Label(remote, text="IP:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(remote, textvariable=self.ip_var, width=14).grid(
            row=0, column=1, padx=4)
        ttk.Label(remote, text="Port:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.target_port_var = tk.StringVar(value="5000")
        ttk.Entry(remote, textvariable=self.target_port_var, width=14).grid(
            row=1, column=1, padx=4)
        self.connect_btn = ttk.Button(remote, text="Connect",
                                      command=self._connect_peer)
        self.connect_btn.grid(row=0, column=2, rowspan=2,
                              padx=(10, 0), sticky=tk.NS)

        # -- Connected peers list --
        self.peers_frame = ttk.LabelFrame(
            top, text="Connected Peers (0) - select one to send privately",
            padding=4)
        self.peers_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.peers_list = tk.Listbox(self.peers_frame, height=6,
                                     exportselection=False,
                                     selectmode=tk.SINGLE,
                                     activestyle="dotbox")
        peers_scroll = ttk.Scrollbar(self.peers_frame, orient=tk.VERTICAL,
                                     command=self.peers_list.yview)
        self.peers_list.config(yscrollcommand=peers_scroll.set)
        self.peers_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        peers_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        # Live target indicator follows the selection.
        self.peers_list.bind("<<ListboxSelect>>",
                             lambda _e: self._update_target_label())

        # ---- Status bar -------------------------------------------------
        self.status_var = tk.StringVar(
            value=f"Peer stopped - received files are saved to: "
                  f"{p2p_node.DOWNLOADS_DIR}")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN,
                  anchor=tk.W, padding=(6, 2)).pack(fill=tk.X, padx=8,
                                                    pady=(4, 0))

        # ---- Message / event log -----------------------------------------
        log_frame = ttk.LabelFrame(self.root, text="Messages & Event Log",
                                   padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.log = scrolledtext.ScrolledText(log_frame, height=16,
                                             state=tk.DISABLED,
                                             wrap=tk.WORD,
                                             font=("Consolas", 10))
        self.log.pack(fill=tk.BOTH, expand=True)
        for level, color in LOG_COLORS.items():
            self.log.tag_configure(level, foreground=color)

        # ---- Bottom bar: message input + send + file ----------------------
        bottom = ttk.Frame(self.root, padding=(8, 4))
        bottom.pack(fill=tk.X)
        self.msg_var = tk.StringVar()
        self.msg_entry = ttk.Entry(bottom, textvariable=self.msg_var)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda _e: self._send_text())
        self.send_btn = ttk.Button(bottom, text="Send",
                                   command=self._send_text)
        self.send_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.file_btn = ttk.Button(bottom, text="Choose File & Send",
                                   command=self._send_file)
        self.file_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.target_lbl = ttk.Label(bottom, text="-> broadcast to all")
        self.target_lbl.pack(side=tk.LEFT, padx=(10, 0))

    # ==================================================================
    # Widget state management
    # ==================================================================

    def _apply_state(self, started: bool):
        """Enable/disable controls to match the node's running state."""
        self.start_btn.config(state=tk.DISABLED if started else tk.NORMAL)
        self.stop_btn.config(state=tk.NORMAL if started else tk.DISABLED)
        self.connect_btn.config(state=tk.NORMAL if started else tk.DISABLED)
        self.send_btn.config(state=tk.NORMAL if started else tk.DISABLED)
        self.file_btn.config(state=tk.NORMAL if started else tk.DISABLED)
        self.msg_entry.config(state=tk.NORMAL if started else tk.DISABLED)
        self.name_entry.config(state=tk.DISABLED if started else tk.NORMAL)
        self.port_entry.config(state=tk.DISABLED if started else tk.NORMAL)
        if not started:
            self.peers_list.delete(0, tk.END)
            self._peer_rows = []
            self.peers_frame.config(
                text="Connected Peers (0) - select one to send privately")
            self._update_target_label()

    # ==================================================================
    # Callbacks FROM NETWORK THREADS (must be fast, never touch widgets)
    # ==================================================================

    def _on_log(self, level, message):
        self.events.put(("log", level, message))

    def _on_text(self, msg):
        self.events.put(("chat", msg))

    def _on_file(self, ev):
        self.events.put(("file", ev))

    # ==================================================================
    # Main-thread pollers
    # ==================================================================

    def _drain_events(self):
        """Render queued network events on the Tkinter main thread."""
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    _, level, message = event
                    self._append_log(level, message)
                elif kind == "chat":
                    msg = event[1]
                    self._append_log("CHAT",
                                     f"{msg.sender_name}> {msg.message}")
                elif kind == "file":
                    ev = event[1]
                    self._append_log("FILE",
                                     f"{ev.sender_name} sent you "
                                     f"'{ev.filename}' "
                                     f"({protocol.format_size(ev.size)}) "
                                     f"-> {ev.path}")
        except queue.Empty:
            pass
        self.root.after(POLL_MS, self._drain_events)

    def _refresh_peers(self):
        """Rebuild the Connected Peers list from the node's pool."""
        node = self.node
        if node is not None and node.is_running:
            # Remember the current selection so a refresh every 500 ms
            # never steals the user's chosen send target.
            selected_ids = {self._peer_rows[i][0]
                            for i in self.peers_list.curselection()}
            self.peers_list.delete(0, tk.END)
            self._peer_rows = []
            for p in node.get_peer_summaries():
                arrow = "<-in" if p["inbound"] else "out->"
                self.peers_list.insert(
                    tk.END,
                    f"{p['peer_name']} ({p['peer_id']}) {arrow} "
                    f"@ {p['endpoint']}")
                self._peer_rows.append((p["peer_id"], p["peer_name"]))
                if p["peer_id"] in selected_ids:
                    self.peers_list.selection_set(len(self._peer_rows) - 1)
            self.peers_frame.config(
                text=f"Connected Peers ({len(self._peer_rows)}) - "
                     f"select one to send privately")
            self._update_target_label()
        self.root.after(PEERS_POLL_MS, self._refresh_peers)

    # ==================================================================
    # User actions
    # ==================================================================

    def _start_peer(self):
        name = self.name_var.get().strip()
        port = self.port_var.get().strip()
        try:
            node = p2p_node.P2PNode(name, port=port)
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))
            return

        node.set_log_callback(self._on_log)
        node.set_on_text_callback(self._on_text)
        node.set_on_file_callback(self._on_file)
        try:
            node.start()            # binds + spawns threads; fast
        except OSError as exc:
            messagebox.showerror(
                "Could not start peer",
                f"Failed to listen on port {node.port}:\n{exc}")
            return

        self.node = node
        self._apply_state(started=True)
        self.status_var.set(
            f"Running as '{node.peer_name}' ({node.peer_id}) on port "
            f"{node.port} - files are saved to: {p2p_node.DOWNLOADS_DIR}")
        self.msg_entry.focus_set()

    def _stop_peer(self):
        node = self.node
        if node is None:
            return
        node.stop()                 # drains readers; fast in practice
        self.node = None
        self._apply_state(started=False)
        self.status_var.set(
            f"Peer stopped - received files are saved to: "
            f"{p2p_node.DOWNLOADS_DIR}")

    def _connect_peer(self):
        node = self.node
        if node is None or not node.is_running:
            return
        ip = self.ip_var.get().strip()
        port = self.target_port_var.get().strip()
        if not ip or not port:
            messagebox.showwarning("Connect",
                                   "Enter a target IP and port first.")
            return

        def worker():
            # connect_peer blocks up to ~10s (connect + handshake
            # timeouts) - run it OFF the GUI thread so the window
            # never freezes. Every failure is already logged by the
            # node and will appear in the event log.
            try:
                node.connect_peer(ip, port)
            except Exception:
                pass        # reason already logged by the node
        threading.Thread(target=worker, name="gui-connect",
                         daemon=True).start()

    def _selected_peer(self):
        """Return (peer_name, peer_id) of the single selected list entry,
        or (None, None) when nothing is selected (broadcast mode)."""
        sel = self.peers_list.curselection()
        if len(sel) == 1 and 0 <= sel[0] < len(self._peer_rows):
            peer_id, peer_name = self._peer_rows[sel[0]]
            return peer_name, peer_id
        return None, None

    def _update_target_label(self):
        name, peer_id = self._selected_peer()
        if peer_id:
            self.target_lbl.config(text=f"-> private to {name}")
        else:
            self.target_lbl.config(text="-> broadcast to all")

    def _send_text(self):
        node = self.node
        if node is None or not node.is_running:
            return
        text = self.msg_var.get().strip()
        if not text:
            return
        target_name, target_id = self._selected_peer()
        try:
            # Fast (<= 8 KB payload): safe to run on the GUI thread.
            delivered = node.send_text(text, target=target_id)
        except protocol.ProtocolError as exc:
            messagebox.showerror("Message rejected", str(exc))
            return
        if delivered:
            # Own-echo: rendered locally, never sent back by the network.
            if target_id is None:
                self._append_log("SENT", f"you> {text}")
            else:
                self._append_log("SENT", f"you-> {target_name}: {text}")
        self.msg_var.set("")
        self.msg_entry.focus_set()

    def _send_file(self):
        node = self.node
        if node is None or not node.is_running:
            return
        path = filedialog.askopenfilename(title="Choose a file to send")
        if not path:
            return                      # user cancelled the dialog
        target_name, target_id = self._selected_peer()

        def worker():
            # send_file streams the whole file - a big transfer would
            # freeze the window if it ran on the GUI thread. The node
            # logs Sending/progress/delivered/failure lines itself.
            try:
                node.send_file(path, target=target_id)
            except Exception:
                pass        # reason already logged by the node
        threading.Thread(target=worker, name="gui-sendfile",
                         daemon=True).start()

    # ==================================================================
    # Rendering helper (main thread only)
    # ==================================================================

    def _append_log(self, level: str, message: str):
        stamp = time.strftime("%H:%M:%S")
        tags = (level,) if level in LOG_COLORS else ()
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, f"[{stamp}] [{level:>5}] {message}\n", tags)
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

    # ==================================================================
    # Shutdown
    # ==================================================================

    def _on_close(self):
        """Window X: stop the node (readers drain, .part files cleaned)
        and only then destroy the window."""
        if self.node is not None:
            self.node.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    P2PGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()