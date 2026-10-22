#!/usr/bin/env python3
"""SPKI helpers for the ca_policy harness (stdlib only).

  spki.py hash <pem>              sha256 of the raw SubjectPublicKeyInfo bytes, sliced out of the
                                  TBSCertificate: what a tool which writes ca_policy lines should hash
  spki.py spki-hex <pem>          the raw SPKI bytes, hex
  spki.py ecpoint <pem>           first byte of the EC point in the SPKI BIT STRING (02/03 = compressed)
  spki.py strip-null <in> <out>   copy of an RSA certificate whose SPKI AlgorithmIdentifier has no NULL
                                  parameters.  The self-signature goes stale; OpenSSL does not check
                                  the self-signature of a trust anchor by default.

Only definite-length DER is walked; anything else raises.
"""
import base64
import hashlib
import sys


def pem_to_der(path):
    text = open(path, "rb").read().decode("ascii")
    body = text.split("-----BEGIN CERTIFICATE-----", 1)[1].split("-----END CERTIFICATE-----", 1)[0]
    return base64.b64decode("".join(body.split()))


def tlv(b, i):
    """(tag, header length, value length) of the TLV at offset i."""
    tag, ln = b[i], b[i + 1]
    hl = 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported length encoding")
        ln = int.from_bytes(b[i + 2:i + 2 + n], "big")
        hl = 2 + n
    if i + hl + ln > len(b):
        raise ValueError("truncated DER")
    return tag, hl, ln


def children(b, i):
    _, hl, ln = tlv(b, i)
    j, end = i + hl, i + hl + ln
    while j < end:
        _, chl, cln = tlv(b, j)
        yield j, chl + cln
        j += chl + cln


def enc_len(n):
    if n < 0x80:
        return bytes([n])
    s = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(s)]) + s


def split_cert(der):
    kids = list(children(der, 0))
    off, ln = kids[0]
    return der[off:off + ln], kids


def raw_spki(tbs):
    kids = list(children(tbs, 0))
    k = 1 if tbs[kids[0][0]] == 0xA0 else 0  # optional [0] version
    off, ln = kids[k + 5]  # serial, signature, issuer, validity, subject, SPKI
    return tbs[off:off + ln]


def spki_of(path):
    tbs, _ = split_cert(pem_to_der(path))
    return raw_spki(tbs)


def strip_null(src, dst):
    der = pem_to_der(src)
    tbs, kids = split_cert(der)
    spki = raw_spki(tbs)
    with_null = bytes.fromhex("300d06092a864886f70d0101010500")
    _, hl, _ = tlv(spki, 0)
    inner = spki[hl:]
    if not inner.startswith(with_null):
        raise SystemExit("strip-null: not an rsaEncryption SPKI with NULL parameters")
    inner = bytes.fromhex("300b06092a864886f70d010101") + inner[len(with_null):]
    new_spki = b"\x30" + enc_len(len(inner)) + inner
    _, thl, _ = tlv(tbs, 0)
    body = tbs[thl:].replace(spki, new_spki, 1)
    new_tbs = b"\x30" + enc_len(len(body)) + body
    rest = b"".join(der[o:o + n] for o, n in kids[1:])
    cert_body = new_tbs + rest
    new_der = b"\x30" + enc_len(len(cert_body)) + cert_body
    b64 = base64.b64encode(new_der).decode("ascii")
    with open(dst, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\n")
        for i in range(0, len(b64), 64):
            f.write(b64[i:i + 64] + "\n")
        f.write("-----END CERTIFICATE-----\n")


def ec_point_prefix(path):
    spki = spki_of(path)
    kids = list(children(spki, 0))
    off, ln = kids[1]  # BIT STRING
    _, hl, _ = tlv(spki, off)
    return "%02x" % spki[off + hl + 1]  # skip the unused-bits octet


def main(argv):
    if len(argv) == 3 and argv[1] == "hash":
        print(hashlib.sha256(spki_of(argv[2])).hexdigest())
    elif len(argv) == 3 and argv[1] == "spki-hex":
        print(spki_of(argv[2]).hex())
    elif len(argv) == 3 and argv[1] == "ecpoint":
        print(ec_point_prefix(argv[2]))
    elif len(argv) == 4 and argv[1] == "strip-null":
        strip_null(argv[2], argv[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
