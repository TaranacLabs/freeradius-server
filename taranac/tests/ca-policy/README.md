# ca_policy harness

Tests for the fork's per-CA revocation policy (`ca_policy` in a server `tls-config`,
`src/main/tls_ca_policy.c`). Not part of upstream's `make test`; no upstream file is touched.

## Running

On taranac-ci: `~/fr-tests/run.sh capolicy <ref> [<harness-ref>]`. It builds `<ref>` the way
`nac/Dockerfile` does (`--disable-developer`, the product's `--with`/`--without` list) plus
`--enable-werror`, installs it in a throwaway `frtest-fr:product` container and runs
`run.sh` there: `radiusd -fxx` per scenario on 127.0.0.1 and `eapol_test` against it, no
docker-in-docker. To show the tests guard the code, run the harness of the feature branch
against a ref without it: `run.sh capolicy taranac feat/ca-policy`.

By hand, anywhere with `radiusd`, `eapol_test`, OpenSSL >= 3.0 and python3:
`./run.sh <workdir> [scenario ...|fast|vg]`. `vg` runs 4, 5, 8 and 9 with radiusd under valgrind memcheck
and fails on any error or definite-leak record whose stack is in `tls_ca_policy.c` or `cbtls_verify`
(ASan does not exist for gcc on musl); `capolicy` on taranac-ci does it after the main run. The SLOW scenarios 15 and 16 wait for the
300 s `ca_path_reload_interval` and run in the background next to the rest (about 5.5 min
in all).

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

## The marker is a contract

`tls: ca_policy: N entries in <section>` (INFO, printed for every parsed server TLS configuration:
an EAP `tls-config`, and also the `tls` subsection of a `listen` or `client`; N = 0 too) is
how Taranac tells a binary that understands `ca_policy` from one that silently ignores it: an
unknown pair is only reported at debug level 3, and Taranac validates with `radiusd -XC`.
Change its wording only together with Taranac (`validate_watcher.sh`, which counts the
`... entries in tls-config ...` lines only).

## SPKI reference

The policy key is the SHA-256 of the raw SubjectPublicKeyInfo bytes as they are in the
certificate. The reference here is `openssl asn1parse`: the SPKI is the 7th child of the
TBSCertificate (`d=2`; the 6th without a `[0] version`), cut out with
`openssl asn1parse -in ca.pem -offset <O> -length <hl+l> -noout -out spki.der` and hashed with
`sha256sum`. Not `openssl pkey -pubout | openssl dgst`: that re-encodes the key from an
`EVP_PKEY`. `spki.py hash` slices the same bytes out of the TBS, which is what Taranac's
`spki_sha256()` does. Scenario 17 checks daemon = asn1parse = slice and writes the roots and
the three hashes to `<workdir>/spki-fixtures/` (the fixture for Taranac's unit test).

Three roots have non-standard SPKI encodings: EC with a compressed point (the key goes through
`openssl ec -conv_form compressed` first; `genpkey -pkeyopt point-format` does not reach the
certificate), RSA-PSS, and RSA without the NULL parameters. The last one is built by
`spki.py strip-null`: it rewrites the AlgorithmIdentifier in the TBS of an ordinary RSA root.
The root's self-signature goes stale, which is fine: OpenSSL does not check the
self-signature of a trust anchor unless `X509_V_FLAG_CHECK_SS_SIGNATURE` is set, and the leaf
and the CRL are signed with the real key.

## Scenarios

FreeRADIUS sets `X509_V_FLAG_PARTIAL_CHAIN`, so OpenSSL ends the verified chain at the first
trusted CA: with the intermediates in `ca_file` (as Taranac deploys them) the chain is only
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
| 5 | R2→P→I: {P}+CRL P / {I}+CRL I / {P,I} | i-ok Reject 3 / i-ok Accept, i-rev Reject 23 / same |
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
| 20 | OCSP on, unconfigured U with a responder | recorded as is (the OCSP task changes it) |
| 21 | loop of cross-certificates A' (A under B) and B' (B under A), only those trusted | the walk ends: {S}: Accept; {B}: Reject 3 |
| 22 | Qold, Qnew: same DN, other keys; Sq under Qnew without AKID; policy {Qnew} | Reject 3 with either bundle order; control {U}: Accept |
| 23 | the client certificate itself trusted (a chain of one) | {S}: Accept + "trusted directly" WARN with its key; {U}, U trusted: Reject 3/33 |
| 24 | 15 u-ok + 5 s-rev at once | all verdicts right, exactly one WARN for U |
