# identify_by = nas_identifier harness

Tests for the fork's clients selected by NAS-Identifier (`identify_by = nas_identifier` with
`nas_identifier "<value>" { ... }` entries in a `client` section; `src/main/client_nas_id.c`,
`src/main/listen_nas_id.c`, syntax in `raddb/clients.conf`). Not part of upstream's
`make test`; no upstream file is touched.

## Running

Build and install the branch (`make install`), then, as root with `CAP_NET_ADMIN`, anywhere with
`radiusd`, `radclient`, `bash` and `ip` (iproute2 or busybox):

    ./run.sh <workdir> [check errors main ratelimit drops stock]

The harness adds the source addresses it sends from (`10.77.0.1`, `10.77.0.5`, `10.77.0.9`,
`10.66.0.1`, `10.66.0.2`, `10.55.0.1`, `10.88.0.1`, `fd00:77::1`) to `lo`: a packet sent to a
local address leaves from that address, so the address `radclient` sends to is the source address
`radiusd` sees. Run it in a throwaway container:

    docker run --rm --network none --cap-add NET_ADMIN \
        --sysctl net.ipv6.conf.all.disable_ipv6=0 <image> run.sh /tmp/w

Every scenario starts its own `radiusd` (`-fxx`; `ratelimit` runs it in daemon mode, `-f`) on
ports 1812/1813 of `*` and `::`. Output: `<workdir>/results.tsv`, `<workdir>/summary.md`, and a
directory per scenario with the raddb, `radiusd.log` and one log per probe (radclient output
followed by the server log written during the probe).

To show that the tests guard the code, run the harness against a build without the feature: every
scenario but `stock` fails (that daemon refuses an `identify_by` client without a
secret of its own, and ignores `identify_by` and the entries otherwise).

## Scenarios

- `check` — `radiusd -XC` accepts the main configuration and prints the marker line for every
  identify_by client.
- `errors` — configurations `radiusd -XC` must refuse, each with its message: entries without
  `identify_by`, an unknown `identify_by` value, `proto = tcp`, an entry with
  `require_message_authenticator = no`, a duplicate entry, an entry without a secret, `identify_by`
  without entries, an empty NAS-Identifier, an unknown `virtual_server`, two identify_by clients
  with the same prefix, a `tls` subsection.
- `main` — Access-Request, Accounting-Request and Status-Server probes: the right secret by
  NAS-ID, two NAS-IDs behind one address with different secrets, the wrong secret, no
  Message-Authenticator, unknown / missing / repeated NAS-ID, an escaped NAS-ID in the log, an
  entry's `virtual_server`, any source (`0.0.0.0/0`, `::/0`), the longest prefix among identify_by
  clients, IPv6, precedence against address clients (an entry wins over an exact `/32` client; with
  no entry the usual longest-prefix match runs and skips an identify_by client without a secret),
  an identify_by client with a secret of its own, and accounting (verified by the Request
  Authenticator, no Message-Authenticator needed).
- `ratelimit` — 20 dropped packets from one source in daemon mode give one log line (two if the
  burst crosses a second); a second source gets its own line.
- `drops` — daemon mode (`-f`): packets from a known client which radiusd used to drop with a
  message only in debug mode now log an `Ignoring request ...` line (`src/main/listen_drop.c`):
  no Message-Authenticator where the client (`require_message_authenticator = yes`) or a
  NAS-Identifier entry requires it, Proxy-State without Message-Authenticator under
  `limit_proxy_state`, Status-Server without Message-Authenticator, a packet code the port does
  not accept (radclient, and a raw code 99), malformed packets sent raw with bash's `/dev/udp`
  (short attribute, attribute 0, attribute header overflow, datagram shorter than its Length
  field, Length < 20, 3-byte datagram, IPv6, a source only an identify_by client covers). A bad
  header from an address no client covers logs nothing. 20 drops from one source give one line
  (two if the burst crosses a second), and the User-Name is in no line. The probes are a second
  apart because of the per-source limit.
- `stock` — without identify_by clients the receive path is upstream's: address clients answer,
  unknown sources are dropped with the upstream message. These rows pass on a binary without the
  feature too; they guard against regressions, they are not evidence that the patch works.

## Verdict rules

- **accept:`<name>`** — `radclient` gets Access-Accept and `Reply-Message` is `<name>`: the server
  copies `%{Client-Shortname}` into it, so it names the entry or client the request was given. The
  server accepts only the password `pw`, so an Accept also proves User-Password was decrypted with
  that entry's secret, and `radclient` checks the reply authenticator with the secret it sent with.
- **acct:`<name>`** — Accounting-Response with `Reply-Message` `<name>`.
- **status** — Access-Accept to Status-Server.
- **reject** — Access-Reject.
- **drop:`<regex>`** — no reply, and the server log written during the probe matches `<regex>`
  (the reason: `invalid Message-Authenticator`, `does not contain required Message-Authenticator`,
  `invalid Request Authenticator`, or the `Ignoring request ...` line of `listen_nas_id.c`).

## The marker is a contract

`client <name>: identify_by nas_identifier: N entries` (INFO, with
`, other packets use the client secret` when the client has a secret of its own) is how a tool
which writes the configuration tells a binary that understands `identify_by` from one which
ignores it: an older binary refuses an identify_by client without a secret, but silently treats
one with a secret as an ordinary client. Do not change its wording.
