# rlm_python3 unicode_errors harness

Tests for the `unicode_errors` option of `rlm_python3` (`src/modules/rlm_python3/rlm_python3.c`,
documented in `raddb/mods-available/python3`): how attribute values which are not valid UTF-8
reach the Python functions. Not part of upstream's `make test`; no upstream file is touched.

## Running

Build and install the branch with `rlm_python3` (`make install`), then, anywhere with `radiusd`,
`radclient`, `python3`, `bash` and `od`:

    ./run.sh <workdir> [check errors main]

Every probe goes to and from 127.0.0.1, so no capability or extra address is needed; a throwaway
container is enough:

    docker run --rm --network none -v "$PWD:/h:ro" <image> /h/run.sh /tmp/w

`main` starts one `radiusd -fxx` with four `python3` instances which differ only in
`unicode_errors` (none, `replace`, `ignore`, `backslashreplace`), each behind its own auth port
(1812, 1822, 1832, 1842) and virtual server. The Python function records, per call, the
instance, the NAS-Identifier (the probe's case tag), `ascii()` of User-Name and User-Password,
and whether any request value holds a NUL. Output: `<workdir>/results.tsv`,
`<workdir>/summary.md`, and a directory per scenario with the raddb, `radiusd.log`, `seen.tsv`
and one log slice per raw probe.

To show that the tests guard the code, run the harness against a build without the option: the
`errors` rows and every `main` row expected to reach Python with a non-UTF-8 value fail (that
daemon ignores the unknown `unicode_errors` item, so every instance behaves as the one without
it): against `taranac-1.3.5` 29 of the 63 cases fail. `check` and the rows where all four
instances agree pass there too; they guard against regressions, they are not evidence that the
patch works.

## Scenarios

- `check` — `radiusd -XC` accepts the configuration with every allowed handler, and with
  `unicode_errors = strict`.
- `errors` — `radiusd -XC` refuses, with `Invalid 'unicode_errors' value "<v>"`: an unknown
  name, the encode-only handlers `xmlcharrefreplace` and `namereplace`, `surrogateescape` and
  `surrogatepass` (they give lone surrogates), a name in the wrong case, and an empty value; and
  `radiusd` with an unknown name does not start.
- `main` —
  - raw Access-Requests (bash's `/dev/udp`, no Message-Authenticator) with User-Name octets:
    ASCII, valid 2-, 3- and 4-byte UTF-8 (unchanged in every instance), `\377bob`, a cp1251-style
    name, valid followed by invalid, a truncated sequence, an encoded surrogate, and NULs before,
    after and between the bytes (the value ends at the first NUL in every instance, as before);
    without the option every non-UTF-8 value fails the call with `mod_populate_vps failed`;
  - a debug line `User-Name is not valid UTF-8, decoding it with unicode_errors = replace` for a
    value that needed the handler, and none for a valid one;
  - radclient, PAP with the right secret and a UTF-8 password: unchanged;
  - radclient (one run per request: `-c 20` stops repeating after the first request without a
    valid reply, and radclient 3.2.10 crashes after a second reply it cannot verify), 20
    requests with User-Name `\377bob`: none reaches Python without the option, all 20 reach it
    as `\ufffdbob` with `replace`;
  - radclient, 20 PAP requests with the wrong secret and `Message-Authenticator !* ANY`
    (radclient adds Message-Authenticator to every Access-Request unless told not to): without
    the option at least 15 fail the call (a decrypted password is valid UTF-8 up to its first NUL
    in about 1 of 100), with `replace` all 20 reach Python, at least 15 with U+FFFD, none with a
    NUL;
  - control: the same wrong-secret request with Message-Authenticator is dropped
    (`invalid Message-Authenticator`) before any module runs.
