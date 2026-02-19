#!/usr/bin/env python3
"""
niri_sticky.py — Make a floating window "sticky" in the niri window manager.

Whenever you switch workspaces the target window is moved there so it is
always visible.  When niri exits this script exits too.  Killing the target
app does NOT exit this script; it will reattach when the app is relaunched.

Usage:
    python3 niri_sticky.py --app-id=mpv

Requirements:
    - niri must be running ($NIRI_SOCKET is set automatically in a niri session)
"""

import argparse
import json
import os
import signal
import socket
import sys


SOCKET_PATH = os.environ.get("NIRI_SOCKET", "")


# ---------------------------------------------------------------------------
# Raw IPC helpers — no subprocess, everything over Unix sockets
# ---------------------------------------------------------------------------

def _connect() -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(SOCKET_PATH)
    return sock


def _send(sock: socket.socket, request) -> dict:
    """Send one JSON request and read back the single-line reply."""
    sock.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("niri IPC socket closed")
        buf += chunk
    return json.loads(buf.split(b"\n", 1)[0])


def ipc_action(request) -> None:
    """Open a fresh connection, fire an action request, close."""
    with _connect() as sock:
        _send(sock, request)


def move_window_to_workspace(window_id: int, workspace_id: int) -> None:
    ipc_action({
        "Action": {
            "MoveWindowToWorkspace": {
                "window_id": window_id,
                "reference": {"Id": workspace_id},
                "focus": False,
            }
        }
    })


def close_window(window_id: int) -> None:
    try:
        ipc_action({"Action": {"CloseWindow": {"id": window_id}}})
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Event stream
# ---------------------------------------------------------------------------

def event_lines(sock: socket.socket):
    """Yield raw JSON lines from the niri event stream."""
    # Subscribe
    sock.sendall(b'"EventStream"\n')
    # Read and discard the {"Ok":"EventStream"} reply
    buf = b""
    while b"\n" not in buf:
        buf += sock.recv(4096)
    buf = buf.split(b"\n", 1)[1]   # keep anything after the reply line

    # Stream events
    while True:
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return
            buf += chunk
        line, buf = buf.split(b"\n", 1)
        if line:
            yield line


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(app_id: str) -> None:
    # window id → workspace id, built from WindowOpenedOrChanged / WindowClosed
    windows: dict[int, int | None] = {}
    focused_ws_id: int | None = None
    target_id: int | None = None   # current window id for app_id
    niri_exited = False

    def cleanup(signum=None, frame=None):
        if target_id is not None and not niri_exited:
            print(f"[niri-sticky] Closing window {target_id}.")
            close_window(target_id)
        sys.exit(0)

    signal.signal(signal.SIGTERM, cleanup)
    signal.signal(signal.SIGINT, cleanup)

    print(f"[niri-sticky] Waiting for '{app_id}' …")

    try:
        with _connect() as ev_sock:
            for raw in event_lines(ev_sock):
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue

                # ---- track all windows (workspace membership) ----
                if "WindowOpenedOrChanged" in event:
                    w = event["WindowOpenedOrChanged"]["window"]
                    wid = w["id"]
                    windows[wid] = w.get("workspace_id")
                    if w.get("app_id") == app_id:
                        if target_id != wid:
                            target_id = wid
                            print(f"[niri-sticky] Attached to window {target_id}.")

                elif "WindowClosed" in event:
                    wid = event["WindowClosed"]["id"]
                    windows.pop(wid, None)
                    if wid == target_id:
                        target_id = None
                        print(f"[niri-sticky] '{app_id}' closed — waiting for relaunch.")

                # ---- workspace switch ----
                elif "WorkspaceActivated" in event:
                    data = event["WorkspaceActivated"]
                    if not data.get("focused", False):
                        continue
                    new_ws = data["id"]
                    if new_ws == focused_ws_id:
                        continue
                    focused_ws_id = new_ws

                    if target_id is None:
                        continue  # app not open right now

                    # Only move if the window isn't already on this workspace
                    if windows.get(target_id) == new_ws:
                        continue

                    move_window_to_workspace(target_id, new_ws)
                    windows[target_id] = new_ws
                    print(f"[niri-sticky] Moved window {target_id} → workspace {new_ws}.")

    except (ConnectionError, OSError) as e:
        print(f"[niri-sticky] Lost IPC connection ({e}). niri exited.")
        niri_exited = True
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Make a floating niri window sticky across all workspaces."
    )
    parser.add_argument(
        "--app-id", required=True,
        help="app-id of the window to make sticky (e.g. 'mpv')"
    )
    args = parser.parse_args()

    global SOCKET_PATH
    SOCKET_PATH = os.environ.get("NIRI_SOCKET", "")
    if not SOCKET_PATH:
        sys.exit("ERROR: NIRI_SOCKET is not set. Run inside a niri session.")

    run(args.app_id)


if __name__ == "__main__":
    main()
