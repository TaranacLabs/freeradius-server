#!/usr/bin/env python3
"""A minimal RADIUS client for the refused-server harness.

Builds one request, sends it (the same octets every time, as a NAS
retransmits), and counts the datagrams which come back on its socket,
whether or not they verify.  Prints "replies=<n>" (and the code of the
first reply), so that "the server did not answer" is observed directly.

    nas.py [options] <host> <port> <secret>
"""
import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
import time

ACCESS_REQUEST = 1
ACCOUNTING_REQUEST = 4
STATUS_SERVER = 12
CODES = {"auth": ACCESS_REQUEST, "acct": ACCOUNTING_REQUEST, "status": STATUS_SERVER}


def attr(num, value):
    return struct.pack("!BB", num, len(value) + 2) + value


def vsa(vendor, subs):
    """One Vendor-Specific attribute holding every (type, value) in subs."""
    body = b"".join(struct.pack("!BB", t, len(v) + 2) + v for t, v in subs)
    return attr(26, struct.pack("!I", vendor) + body)


def pap(password, secret, vector):
    """User-Password, RFC 2865 section 5.2."""
    p = password + b"\x00" * (-len(password) % 16) if password else b"\x00" * 16
    out, last = b"", vector
    for i in range(0, len(p), 16):
        b = hashlib.md5(secret + last).digest()
        last = bytes(x ^ y for x, y in zip(p[i:i + 16], b))
        out += last
    return out


def build(args, ident, vector):
    secret = args.secret.encode()
    attrs = b""
    if args.user is not None:
        attrs += attr(1, args.user.encode())
    if args.password is not None:
        attrs += attr(2, pap(args.password.encode(), secret, vector))
    if args.chap:
        # CHAP-Password: ident + 16 octets; its check needs no secret
        attrs += attr(3, b"\x01" + b"C" * 16)
    if args.nas_id is not None:
        attrs += attr(32, args.nas_id.encode())
    if args.code == "acct":
        attrs += attr(40, struct.pack("!I", 1))  # Acct-Status-Type = Start
        attrs += attr(44, b"session-1")          # Acct-Session-Id
    if args.tunnel_password:
        # tag, salt (high bit set), 16 encrypted octets
        attrs += attr(69, b"\x00\x80\x01" + b"T" * 16)
    if args.mppe:
        # MS-MPPE-Send-Key (Microsoft 16): salt and 32 encrypted octets
        attrs += vsa(311, [(16, b"\x80\x02" + b"K" * 32)])
    if args.vsa_count:
        # Cisco-AVPair (Cisco 1) times n, all inside ONE Vendor-Specific
        attrs += vsa(9, [(1, b"a=%d" % i) for i in range(args.vsa_count)])

    code = CODES[args.code]
    ma = args.ma if args.ma is not None else code != ACCOUNTING_REQUEST
    if ma:
        attrs += attr(80, b"\x00" * 16)
    length = 20 + len(attrs)
    if code == ACCOUNTING_REQUEST:
        auth = b"\x00" * 16
    else:
        auth = vector
    pkt = bytearray(struct.pack("!BBH", code, ident, length) + auth + attrs)
    if ma:
        mac = hmac.new(secret, bytes(pkt), hashlib.md5).digest()
        pkt[-16:] = mac
    if code == ACCOUNTING_REQUEST:
        pkt[4:20] = hashlib.md5(bytes(pkt) + secret).digest()
    return bytes(pkt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("secret")
    ap.add_argument("--code", choices=sorted(CODES), default="auth")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--nas-id")
    ap.add_argument("--chap", action="store_true")
    ap.add_argument("--tunnel-password", action="store_true")
    ap.add_argument("--mppe", action="store_true")
    ap.add_argument("--vsa-count", type=int, default=0)
    ap.add_argument("--ma", dest="ma", action="store_true", default=None,
                    help="add Message-Authenticator (default: yes, but not for acct)")
    ap.add_argument("--no-ma", dest="ma", action="store_false")
    ap.add_argument("--send", type=int, default=1, help="send the same octets this many times")
    ap.add_argument("--gap", type=float, default=0.0, help="seconds between sends")
    ap.add_argument("--wait", type=float, default=1.0, help="seconds to wait for replies after the last send")
    args = ap.parse_args()

    fam = socket.AF_INET6 if ":" in args.host else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    s.connect((args.host, args.port))
    pkt = build(args, os.getpid() & 0xff, os.urandom(16))

    replies, first = 0, None

    def drain(until):
        nonlocal replies, first
        while True:
            left = until - time.monotonic()
            if left <= 0:
                return
            s.settimeout(left)
            try:
                data = s.recv(4096)
            except socket.timeout:
                return
            except ConnectionRefusedError:
                continue
            replies += 1
            if first is None and data:
                first = data[0]

    for i in range(args.send):
        s.send(pkt)
        if i + 1 < args.send:
            drain(time.monotonic() + args.gap)
    drain(time.monotonic() + args.wait)
    print("replies=%d%s" % (replies, "" if first is None else " code=%d" % first))
    return 0


if __name__ == "__main__":
    sys.exit(main())
