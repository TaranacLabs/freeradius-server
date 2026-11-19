#!/usr/bin/env python3
"""Measure how a burst of refused packets delays a valid request from another client.

Sends <count> Access-Requests without Message-Authenticator from <refused source> (a client
which requires one) as fast as it can, while another client sends valid Access-Requests one
at a time and times each round trip.  Before the burst, the same valid requests are timed
alone (the baseline).

    burst.py <host> <port> <refused source> <refused secret> <valid secret> <count> [<chunk> <gap ms> [valid]]

With <chunk>, the burst is sent <chunk> packets at a time, <gap ms> apart; without it, as fast
as one socket can send, which overflows radiusd's socket buffer (the kernel drops them).
With "valid", the burst is of correctly signed requests instead (with Message-Authenticator):
the same load as ordinary traffic, for comparison.

Prints one line of key=value pairs: the baseline and in-burst round trips (median and max,
milliseconds), how many valid requests were sent and answered during the burst, how long the
burst took to send, and the kernel's UDP receive buffer errors during the burst
(/proc/net/snmp): datagrams, refused or valid, which never reached radiusd.
"""
import hashlib
import hmac
import os
import socket
import statistics
import struct
import sys
import threading
import time


def attr(num, value):
    return struct.pack("!BB", num, len(value) + 2) + value


def request(ident, secret, user, nas_id, ma):
    vector = os.urandom(16)
    attrs = attr(1, user) + attr(32, nas_id)
    if ma:
        attrs += attr(80, b"\x00" * 16)
    pkt = bytearray(struct.pack("!BBH", 1, ident, 20 + len(attrs)) + vector + attrs)
    if ma:
        pkt[-16:] = hmac.new(secret, bytes(pkt), hashlib.md5).digest()
    return bytes(pkt)


def rcvbuf_errors():
    with open("/proc/net/snmp") as f:
        rows = [line.split() for line in f if line.startswith("Udp:")]
    return int(dict(zip(rows[0], rows[1]))["RcvbufErrors"])


def timed(sock, ident, secret):
    sock.send(request(ident, secret, b"valid", b"burst_valid", True))
    t = time.monotonic()
    sock.settimeout(2.0)
    try:
        sock.recv(4096)
    except socket.timeout:
        return None
    return (time.monotonic() - t) * 1000.0


def main():
    host, port, src, refused_secret, valid_secret, count = sys.argv[1:7]
    port, count = int(port), int(count)
    chunk = int(sys.argv[7]) if len(sys.argv) > 7 else 0
    gap = float(sys.argv[8]) / 1000.0 if len(sys.argv) > 8 else 0.0
    flood_ma = len(sys.argv) > 9 and sys.argv[9] == "valid"
    refused_secret, valid_secret = refused_secret.encode(), valid_secret.encode()
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET

    valid = socket.socket(fam, socket.SOCK_DGRAM)
    valid.connect((host, port))

    base = []
    for i in range(20):
        base.append(timed(valid, i, valid_secret))
        time.sleep(0.01)

    sent = [0, 0.0]

    def flood():
        t = time.monotonic()
        sock = None
        for i in range(count):
            # a new source port every 200 packets: IDs do not repeat on one port
            if i % 200 == 0:
                sock = socket.socket(fam, socket.SOCK_DGRAM)
                sock.bind((src, 0))
                sock.connect((host, port))
            sock.send(request(i & 0xff, refused_secret, b"flood", b"burst", flood_ma))
            sent[0] += 1
            if chunk and (i + 1) % chunk == 0:
                time.sleep(gap)
        sent[1] = (time.monotonic() - t) * 1000.0

    errors = rcvbuf_errors()
    th = threading.Thread(target=flood)
    th.start()
    during = []
    ident = 100
    while th.is_alive() or len(during) < 5:
        during.append(timed(valid, ident & 0xff, valid_secret))
        ident += 1
    th.join()
    time.sleep(0.5)
    errors = rcvbuf_errors() - errors

    def stats(rtts):
        ok = [r for r in rtts if r is not None]
        if not ok:
            return "none", "none"
        return "%.2f" % statistics.median(ok), "%.2f" % max(ok)

    bmed, bmax = stats(base)
    dmed, dmax = stats(during)
    print("baseline_median_ms=%s baseline_max_ms=%s burst_median_ms=%s burst_max_ms=%s "
          "valid_sent=%d valid_answered=%d refused_sent=%d burst_send_ms=%.1f rcvbuf_errors=%d"
          % (bmed, bmax, dmed, dmax, len(during), sum(1 for r in during if r is not None),
             sent[0], sent[1], errors))
    return 0


if __name__ == "__main__":
    sys.exit(main())
