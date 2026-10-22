"""Misbehaving network peers for the per-CA OCSP scenarios (38, 39), all on 127.0.0.1.

    python3 -I net_stub.py blackhole <port>   a TCP listener whose accept queue is full:
                                              listen(0) and never accept, after filling the
                                              queue with our own connections, so that a new
                                              SYN is dropped and connect() hangs
    python3 -I net_stub.py silent <port>      accepts and never answers
    python3 -I net_stub.py dns <mode> [port]  a DNS server on UDP <port> (default 53):
                                              nxdomain = answers NXDOMAIN to everything,
                                              silent = reads queries and never answers
Runs until killed.  Prints one line when ready.
"""

import socket
import sys
import threading
import time


def blackhole(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(0)
    held = []
    # Linux keeps backlog + 1 connections in the accept queue; fill it, then a few more
    # attempts which must hang (non-blocking connects, never completed)
    for _ in range(4):
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.setblocking(False)
        try:
            c.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        held.append(c)
        time.sleep(0.05)
    # check: a new blocking connect must not complete within 1 s
    t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    t.settimeout(1.0)
    try:
        t.connect(("127.0.0.1", port))
        print(f"blackhole {port}: NOT a black hole (connect completed)", flush=True)
    except (socket.timeout, OSError) as e:
        print(f"blackhole {port}: ready (probe connect: {type(e).__name__})", flush=True)
    t.close()
    while True:
        time.sleep(3600)


def silent(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(128)
    print(f"silent {port}: ready", flush=True)
    held = []
    while True:
        c, _ = s.accept()
        held.append(c)


def dns(mode, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", port))
    print(f"dns {mode} {port}: ready", flush=True)
    while True:
        q, addr = s.recvfrom(4096)
        if mode != "nxdomain" or len(q) < 12:
            continue
        # header: same id, QR=1, opcode, RD copied, RA=1, RCODE=3; question copied
        flags = 0x8000 | (q[2] & 0x79) << 8 | 0x0080 | 3
        r = q[0:2] + flags.to_bytes(2, "big") + q[4:6] + b"\0\0\0\0\0\0" + q[12:]
        s.sendto(r, addr)


if __name__ == "__main__":
    kind = sys.argv[1]
    if kind == "blackhole":
        blackhole(int(sys.argv[2]))
    elif kind == "silent":
        silent(int(sys.argv[2]))
    elif kind == "dns":
        threading.Thread(target=dns, args=(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 53),
                         daemon=True).start()
        threading.Event().wait()
