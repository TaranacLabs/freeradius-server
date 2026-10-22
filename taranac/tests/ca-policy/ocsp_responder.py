"""Controllable OCSP responder for the ca_policy harness (per-CA OCSP scenarios 31-45).

    python3 -I ocsp_responder.py <pki dir> <state.json> <requests.log> <port> [<port> ...]

Listens on 127.0.0.1 on every port given.  The state is re-read on EVERY request, so a
scenario changes behaviour by rewriting state.json, without a restart.  Every request is
appended as one JSON line to requests.log (that file is the request counter).

The PKI is the harness one (pki.sh): CA certificates at <pki>/<CA>/cert.pem with keys
<pki>/<CA>/key.pem, leaves at <pki>/leaf/<name>.pem + .key.

state.json keys (all optional):
  serves        [CA names]  the CAs it answers for; any other issuer of the CertID gets
                "unauthorized" (Microsoft's Online Responder without a Revocation Configuration
                for that CA).  Default: every CA of the PKI.
  status        {"<leaf>": "good|revoked|unknown"}            default good
  signer        "issuer" | "leaf:<leaf>" | "<cert>" where <cert> is leaf/<cert>.pem + .key
                (a delegated responder)                          default issuer
  include_cert  bool, put the signer certificate in the response default true
  nonce         echo | omit                                      default echo
  this_update   seconds relative to now                          default -60
  next_update   seconds relative to now, null = field absent     default 3600
  delay         seconds to sleep before answering                default 0
  resp_status   successful | tryLater | unauthorized | internalError | malformedRequest | sigRequired
  http_status   int                                              default 200
  body          "garbage" = a body which is not DER
  drip          seconds between bytes of the answer (a slow responder)
  other_serial  true: the SingleResponse is for another serial of the same issuer
  corrupt_sig   true: flip the last byte of the response (with include_cert false, that is the
                signature), so that the signature does not verify
"""

import datetime as dt
import glob
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

PKI, STATE, LOG = sys.argv[1], sys.argv[2], sys.argv[3]
PORTS = [int(p) for p in sys.argv[4:]]
LOCK = threading.Lock()


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), None)


CAS = {}  # name -> (cert, key)
for d in sorted(glob.glob(f"{PKI}/*/cert.pem")):
    name = os.path.basename(os.path.dirname(d))
    if name == "leaf":
        continue
    CAS[name] = (load_cert(d), load_key(os.path.join(os.path.dirname(d), "key.pem")))
LEAVES = {}  # name -> (cert, key)
for p in sorted(glob.glob(f"{PKI}/leaf/*.pem")):
    name = os.path.basename(p)[:-4]
    if name.endswith((".csr",)) or name.startswith("server_chain"):
        continue
    try:
        LEAVES[name] = (load_cert(p), load_key(p[:-4] + ".key"))
    except ValueError:
        pass
BY_SERIAL = {}
for n, (c, _) in LEAVES.items():
    BY_SERIAL.setdefault(c.serial_number, []).append(n)


def issuer_of(req):
    """The CA whose name and key hashes are in the CertID (first match, in name order).

    The key hash is taken from a probe request (add_certificate() hashes the issuer's key); the
    name hash is computed here, as add_certificate() hashes cert.issuer, not the issuer's subject.
    """
    for n, (c, _) in CAS.items():
        probe = ocsp.OCSPRequestBuilder().add_certificate(c, c, req.hash_algorithm).build()
        name_hash = hashlib.new(req.hash_algorithm.name, c.subject.public_bytes()).digest()
        if probe.issuer_key_hash == req.issuer_key_hash and name_hash == req.issuer_name_hash:
            return n
    return None


def leaf_for(serial, iss):
    for n in BY_SERIAL.get(serial, []):
        c, _ = LEAVES[n]
        if c.issuer == CAS[iss][0].subject:
            return n
    return None


def state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


STATUS = {
    "tryLater": ocsp.OCSPResponseStatus.TRY_LATER,
    "unauthorized": ocsp.OCSPResponseStatus.UNAUTHORIZED,
    "internalError": ocsp.OCSPResponseStatus.INTERNAL_ERROR,
    "malformedRequest": ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
    "sigRequired": ocsp.OCSPResponseStatus.SIG_REQUIRED,
}
CS = {"good": ocsp.OCSPCertStatus.GOOD, "revoked": ocsp.OCSPCertStatus.REVOKED,
      "unknown": ocsp.OCSPCertStatus.UNKNOWN}


def unsuccessful(rs):
    return ocsp.OCSPResponseBuilder.build_unsuccessful(STATUS[rs]).public_bytes(serialization.Encoding.DER)


def pick(spec):
    """(cert, key) for a signer or key spec."""
    if spec.startswith("leaf:"):
        return LEAVES[spec[5:]]
    if spec in CAS:
        return CAS[spec]
    return LEAVES[spec]


def answer(der, st):
    rec = {}
    try:
        req = ocsp.load_der_ocsp_request(der)
    except Exception as e:  # noqa: BLE001
        rec["error"] = f"bad request: {e}"
        return rec, unsuccessful("malformedRequest")
    iss = issuer_of(req)
    name = leaf_for(req.serial_number, iss) if iss else None
    try:
        nonce = req.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
    except x509.ExtensionNotFound:
        nonce = None
    rec.update(cert=name or hex(req.serial_number), issuer=iss, req_nonce=nonce is not None,
               hash=req.hash_algorithm.name)
    rs = st.get("resp_status", "successful")
    if rs != "successful":
        rec["answer"] = rs
        return rec, unsuccessful(rs)
    serves = st.get("serves")
    if iss is None or (serves is not None and iss not in serves) or name is None:
        rec["answer"] = "unauthorized (not served)"
        return rec, unsuccessful("unauthorized")
    icert, ikey = CAS[iss]
    status = st.get("status", {}).get(name, "good")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    this_up = now + dt.timedelta(seconds=st.get("this_update", -60))
    nu = st.get("next_update", 3600)
    next_up = None if nu is None else now + dt.timedelta(seconds=nu)

    targets = [name]
    if st.get("other_serial"):
        targets = [n for n, (c, _) in LEAVES.items() if n != name and c.issuer == icert.subject][:1]
    b = ocsp.OCSPResponseBuilder()
    for t in targets:
        b = b.add_response(
            cert=LEAVES[t][0], issuer=icert, algorithm=req.hash_algorithm, cert_status=CS[status],
            this_update=this_up, next_update=next_up,
            revocation_time=(now - dt.timedelta(hours=1)) if status == "revoked" else None,
            revocation_reason=x509.ReasonFlags.key_compromise if status == "revoked" else None,
        )
    sname = st.get("signer", "issuer")
    scert, skey = (icert, ikey) if sname == "issuer" else pick(sname)
    b = b.responder_id(ocsp.OCSPResponderEncoding.HASH, scert)
    if st.get("include_cert", True):
        b = b.certificates([scert])
    if nonce is not None and st.get("nonce", "echo") == "echo":
        b = b.add_extension(x509.OCSPNonce(nonce), critical=False)
    rec.update(answer=status, signer=sname, targets=targets, this_update=str(this_up), next_update=str(next_up))
    der = b.sign(skey, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    if st.get("corrupt_sig"):
        der = der[:-1] + bytes([der[-1] ^ 0x01])
    return rec, der


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_POST(self):
        st = state()
        n = int(self.headers.get("Content-Length", "0"))
        der = self.rfile.read(n)
        rec, body = answer(der, st)
        rec.update(t=round(time.time(), 3), port=self.server.server_address[1], path=self.path,
                   method=self.command, host_hdr=self.headers.get("Host"),
                   ctype=self.headers.get("Content-Type"))
        with LOCK, open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        if st.get("delay"):
            time.sleep(st["delay"])
        if st.get("body") == "garbage":
            body = b"this is not DER\n" * 4
        self.send_response(st.get("http_status", 200))
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        drip = st.get("drip")
        if drip:
            for i in range(len(body)):
                self.wfile.write(body[i:i + 1])
                self.wfile.flush()
                time.sleep(drip)
        else:
            self.wfile.write(body)

    do_GET = do_POST

    def log_message(self, *a):
        pass


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


if __name__ == "__main__":
    for p in PORTS:
        s = Server(("127.0.0.1", p), H)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print(f"responder up on {PORTS}: {len(CAS)} CAs, {len(LEAVES)} leaves", flush=True)
    threading.Event().wait()
