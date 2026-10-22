# ca_policy harness

Tests for the fork's per-CA revocation policy (`ca_policy` in a server `tls-config`,
`src/main/tls_ca_policy.c`). Not part of upstream's `make test`; no upstream file is touched.

## Running

Build and install the branch (`make install`), then, anywhere with `radiusd`, `eapol_test`,
OpenSSL >= 3.0 and python3:

    ./run.sh <workdir> [scenario ...|fast|vg|ocsp]

Each scenario starts `radiusd -fxx` on its own port on 127.0.0.1 and runs `eapol_test`
against it. `vg` runs 4, 5, 8 and 9 with radiusd under valgrind memcheck and fails on any
error or definite-leak record whose stack is in `tls_ca_policy.c` or `cbtls_verify`. The
SLOW scenarios 15 and 16 wait for the 300 s `ca_path_reload_interval` and run in the
background next to the rest (about 5.5 min in all). To show that the tests guard the code,
run the harness of this branch against a build without the feature: the scenarios which
need it fail.

The per-CA OCSP scenarios (30-49, `ocsp`, in `ocsp.sh`) also need `radclient`, python3 with
`cryptography`, and root: they add `ocsp.capol.test` to `/etc/hosts` and point
`/etc/resolv.conf` at a stub DNS server, so run them in a throwaway container without a
network (`docker run --network none ...`). `vg` adds 31, 33, 35, 36, 38 and 39 under
valgrind. With `ASAN=1` the harness expects an AddressSanitizer build of radiusd and fails a
scenario on any ASan report whose stack is in our code (`tls_ca_policy*.c`,
`cbtls_verify`).

## Verdict rules

- **Reject N** counts only if `eapol_test` fails and the server log written during that probe
  has `OpenSSL says error N`.
- **Accept** of a chain in which no CA is configured counts only if, since this daemon started,
  the log has the `CRL not checked ... issuer key sha256:<issuer SPKI>` warning for that
  issuer. The daemon logs it once per issuer per X509 store, and every scenario starts a
  fresh daemon, so one line covers every Accept of that issuer in the scenario.
- Every scenario checks the marker `tls: ca_policy: N entries in tls-config tls-nac`, N = number of lines.
- `Reject 23 [regression]` rows give the same verdict on a binary without `ca_policy` (23 is never
  cleared, and a configured chain behaves as upstream). They guard against regressions; they are not
  evidence that the patch works.
- A scenario relying on the store being rebuilt needs `Flushing X509 store` in the log,
  otherwise it is INCONCLUSIVE (exit 2), not a pass.
- RECORD rows are measurements (16: is a new CRL file picked up before the rebuild; 20: OCSP
  with an unconfigured CA), they never fail.

OCSP verdicts (scenarios 30-49):

- **Reject `<verdict>`** counts only if `eapol_test` fails and the server log of that probe
  has `ocsp verdict <verdict>` (`revoked`, `unknown`, or `failed <class>` with one of
  `transport busy response verify config`).
- **Accept, good** counts only if the log has `ocsp verdict good` and the responder logged at
  least one request during the probe; **Accept, not needed** only if there is no verdict line
  and the responder logged none.
- Times (scenario 38) are those of the whole `eapol_test` run; a baseline with a good answer
  is recorded next to them.

## The marker is a contract

`tls: ca_policy: N entries in <section>` (INFO, printed for every parsed server TLS configuration:
an EAP `tls-config`, and also the `tls` subsection of a `listen` or `client`; N = 0 too) is
how a tool which writes the configuration tells a binary that understands `ca_policy` from
one that silently ignores it: an unknown pair is only reported at debug level 3, below what
`radiusd -XC` shows. Do not change its wording.

## SPKI reference

The policy key is the SHA-256 of the raw SubjectPublicKeyInfo bytes as they are in the
certificate. The reference here is `openssl asn1parse`: the SPKI is the 7th child of the
TBSCertificate (`d=2`; the 6th without a `[0] version`), cut out with
`openssl asn1parse -in ca.pem -offset <O> -length <hl+l> -noout -out spki.der` and hashed with
`sha256sum`. Not `openssl pkey -pubout | openssl dgst`: that re-encodes the key from an
`EVP_PKEY`. `spki.py hash` slices the same bytes out of the TBS, which is what a tool writing
`ca_policy` lines should do. Scenario 17 checks daemon = asn1parse = slice and writes the roots and
the three hashes to `<workdir>/spki-fixtures/` (fixtures for the tests of such a tool).

Three roots have non-standard SPKI encodings: EC with a compressed point (the key goes through
`openssl ec -conv_form compressed` first; `genpkey -pkeyopt point-format` does not reach the
certificate), RSA-PSS, and RSA without the NULL parameters. The last one is built by
`spki.py strip-null`: it rewrites the AlgorithmIdentifier in the TBS of an ordinary RSA root.
The root's self-signature goes stale, which is fine: OpenSSL does not check the
self-signature of a trust anchor unless `X509_V_FLAG_CHECK_SS_SIGNATURE` is set, and the leaf
and the CRL are signed with the real key.

## Scenarios

FreeRADIUS sets `X509_V_FLAG_PARTIAL_CHAIN`, so OpenSSL ends the verified chain at the first
trusted CA: with the intermediates in `ca_file` (a common deployment) the chain is only
leaf + issuing CA. Scenarios 4, 5 (first case) and 8 (first case) are the ones that fail if the
hook looks at `X509_STORE_CTX_get0_chain()` alone and does not walk on through the trust store; 21
and 22 check how that walk ends and that every candidate issuer counts.

| # | Setup | Expected |
|---|---|---|
| 0 | `-XC` with two valid lines / with none | exit 0 and marker 2 / marker 0 |
| 1 | `check_crl`, no `ca_policy` | upstream: u-ok Reject 3, s-rev Reject 23 |
| 2 | policy {S} | s-ok Accept, s-rev Reject 23, u-ok Accept twice with one WARN |
| 3 | policy {S} | u-expired Reject 10, u-forged (U's DN, other key) Reject 7 |
| 4 | policy {R}, CRL R only | s-ok Reject 3 (the leaf needs S's CRL) |
| 5 | R2->P->I: {P}+CRL P / {I}+CRL I / {P,I} | i-ok Reject 3 / i-ok Accept, i-rev Reject 23 / same |
| 6 | only R trusted, client sends leaf + S | {R}: Reject 3; {U}: Accept |
| 7 | client sends extra CA certificates | s-rev + U: Reject 23; u-ok + S: Accept |
| 8 | only R' (R re-issued, same key) trusted, policy from R | Reject 3; control {U}: Accept |
| 9 | R, U trusted; client sends leaf + S' (S cross-signed by U) | with CRL S: Reject 23; without: Reject 3 |
| 10 | policy {S}, CRL S expired / not yet valid | Reject 12 / Reject 11 |
| 11 | not hex, 63 chars, unknown flag, no flags, `crl=1`, `""`, spaces only, `CRL`, `crl crl`, duplicate | `-XC` fails naming the line; a tab separator is valid |
| 12 | policy {S}, base + delta CRL | s-drev (revoked in the delta only) Reject 23 |
| 13 | `ca_policy` without `check_crl` | startup WARN, s-rev Accept |
| 14 | PEAP on the same tls-config | Accept |
| 15 | SLOW: CRL S replaced (revokes s-ok), wait for the rebuild | u-ok just before it: still 1 WARN; after: s-ok Reject 23, a 2nd WARN for U |
| 16 | SLOW: CRL S appears without a rebuild | measured; after the rebuild Reject 23 |
| 17 | SPKI of R, U and the three non-standard roots | daemon = asn1parse = slice; fixtures written |
| 18 | the three non-standard roots in the policy, CRLs expired | Reject 12 each |
| 19 | cleared Accept (u-ok) and a checked one (s-ok) | `TLS-Client-Cert-Issuer`/`-Serial` in post-auth |
| 20 | the upstream `ocsp` section on, U (not listed) with a responder | recorded as is |
| 21 | loop of cross-certificates A' (A under B) and B' (B under A), only those trusted | the walk ends: {S}: Accept; {B}: Reject 3 |
| 22 | Qold, Qnew: same DN, other keys; Sq under Qnew without AKID; policy {Qnew} | Reject 3 with either bundle order; control {U}: Accept |
| 23 | the client certificate itself trusted (a chain of one) | {S}: Accept + "trusted directly" WARN with its key; {U}, U trusted: Reject 3/33 |
| 24 | 15 u-ok + 5 s-rev at once | all verdicts right, exactly one WARN for U |

### Per-CA OCSP (`ocsp.sh`)

The responder (`ocsp_responder.py`) answers on 127.0.0.1:17881 (the AIA of the test leaves,
`http://ocsp.capol.test:17881/aia`), 17882 and 17883 (`ocsp_url` A and B); a scenario changes
what it answers by rewriting its `state.json` (status, signer, times, responseStatus, HTTP
status, delay, a body which is not DER, ...), and every request is logged. `net_stub.py`
provides a closed port (17891), a black hole (17892: `listen(0)`, accept queue filled, so a
new connect hangs), a peer which never answers (17893), and DNS servers which answer NXDOMAIN
or nothing.

| # | Setup | Expected |
|---|---|---|
| 30 | `-XC` on valid lines (orders, tabs, IPv6, no path, `HTTP://`) and on errors (`ocsp_url` without `ocsp`, https, ldap, no scheme, bad or 0 port, no host, empty, bare `ocsp_url`, flags twice, `ocsp=1`, `OCSP`, no flags, with `ocsp { enable = yes }`, duplicate key) | exit 0 + marker, WARN only with `crl` / exit != 0 naming the line |
| 31 | {S ocsp}, URL from the AIA: good / revoked / unknown | Accept / Reject revoked (reason, time) / Reject unknown; 1 request each |
| 32 | U not listed; R listed (CertID of S); responder serving only S / only R; R2->P->I with P listed, responder serving I / P | 0 requests Accept; good; good / failed response (unauthorized); good / failed response |
| 33 | URL: override with an AIA (used), caIssuers only + URL, no AIA + URL; no URL and no AIA, caIssuers only, https only; ldap then http; Microsoft layout (OCSP third) | good x3; failed config, 0 requests x3, "responder none"; the http entry; good |
| 34 | responder without nonce | Accept; the request has no nonce, SHA-1 CertID |
| 35 | tryLater, unauthorized, internalError, malformedRequest, sigRequired; HTTP 500; not DER | failed response x5; failed transport x2 |
| 36 | signer: CA with / without its certificate, delegate with / without nocheck; delegate without EKU, bad signature, delegate of another CA, the leaf (with / without its certificate); status for another serial only | good x4; failed verify x6 |
| 37 | nextUpdate -10 / -2 min, thisUpdate +10 / +2 min, no nextUpdate and 1 h / 2 min old | failed verify / good, alternating |
| 38 | refused, black hole, silent, 1 byte per 0.5 s, NXDOMAIN | failed transport within 5.5 / 4.5 / 4.5 / 4.5 / 5.5 s; times recorded |
| 49 | DNS that never answers, `timeout:1 attempts:1` and defaults | failed transport; times recorded |
| 39 | black hole, 8 at once, 32 threads; PEAP meanwhile | 4 transport + 4 busy; each PEAP < 1 s |
| 46 | healthy responder, 32 at once, latency 0 / 20 / 50 ms (recorded) and 100 ms | 32 Accept, 0 busy at 100 ms |
| 47 | black hole, 50 at once, 32 threads; MAB and PEAP meanwhile; then 4 at once for another CA | 50 Reject (transport or busy), at most 8 transport; each MAB / PEAP < 1 s; 4 Accept |
| 48 | 100 rejects of each kind (two transport, response, verify, revoked, unknown, config), 4 at a time; then 4 good at once | all counted, 0 busy; 4 Accept |
| 40 | CRL and OCSP on S: CRL-revoked (no request), OCSP-revoked, both good; response signed by S without R's CRL; U OCSP only next to S crl (CA and delegate signers) | Reject 23 + 0 requests; Reject revoked; good x4 |
| 41 | R and S with URLs: S's is used; S without URL, R with one: the leaf's AIA is used | good, on the expected URL |
| 42 | PEAP and TTLS on the tls-config | Accept, 0 requests |
| 43 | revoked / unknown / failed | the server sends certificate_revoked / certificate_unknown / certificate_unknown |
| 44 | session cache on, `eapol_test -r 1` | recorded: the resumed handshake makes no request |
