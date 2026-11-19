#!/usr/bin/env python3
"""Listen on UDP ports of 127.0.0.1 and never answer.

Appends "<port> <code>" to <log> for every datagram: the harness's home
server (proxy) and CoA server, to see whether radiusd sent anything there.

    sink.py <log> <port> [<port> ...]
"""
import selectors
import socket
import sys


def main():
    log = sys.argv[1]
    sel = selectors.DefaultSelector()
    for port in sys.argv[2:]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", int(port)))
        sel.register(s, selectors.EVENT_READ, int(port))
    open(log, "a").close()
    while True:
        for key, _ in sel.select():
            data = key.fileobj.recv(4096)
            with open(log, "a") as f:
                f.write("%d %d\n" % (key.data, data[0] if data else -1))


if __name__ == "__main__":
    main()
