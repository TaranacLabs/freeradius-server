# refused_virtual_server harness

Tests for the `refused_virtual_server` option of UDP `auth` and `acct` listeners
(`src/main/listen.c`, `src/main/listen_drop.c`, documented in `raddb/sites-available/default`):
a request from a known client which fails its signature check, lacks a required
Message-Authenticator, has a packet code the port does not accept, or does not decode, is run
through the named virtual server with `Refused-Reason` and `Module-Failure-Message`, and is
still dropped without a reply. Not part of upstream's `make test`.

## Running

Build and install the branch (`make install`), then, anywhere with `radiusd`, `radclient`,
`python3`, `bash` and `ip`:

    ./run.sh <workdir> [dictionary check errors signature malformed receive]

Every probe goes to and from 127.0.0.1 or ::1, so no capability or extra address is needed, but
IPv6 must be enabled on `lo`:

    docker run --rm --network none --sysctl net.ipv6.conf.all.disable_ipv6=0 \
        -v "$PWD:/h:ro" <image> /h/run.sh /tmp/w

The configuration has three virtual servers: `s_on` (auth and acct listeners on 127.0.0.1 and
::1 with `refused_virtual_server = refused`), `s_off` (the same on 127.0.0.1 ports 1822/1823,
without the option), and `refused`, which logs one line per run with `linelog`: the probe's
NAS-Identifier as its tag, Refused-Reason, Packet-Type, User-Name, Module-Failure-Message, the
source address, the destination port and every request attribute. `s_on` and `s_off` log each
request they handle to `normal.log`. `sink.py` listens on 127.0.0.1:1912 (a home server) and
:3799 (a CoA server), never answers, and logs what it receives.

`nas.py` is the client for most probes: it sends the same octets as many times as asked (as a
NAS retransmits) and counts every datagram that comes back, verified or not, so "no reply" is
observed rather than inferred from a failed verification; `--src` sends from another
127.0.0.0/8 address (all are local), `--raw` sends given octets. radclient is used too, as a real
client: it adds Message-Authenticator to every Access-Request by itself. `burst.py` times valid
requests while another client floods (see `receive`).

Output: `<workdir>/results.tsv`, `<workdir>/summary.md`, and a directory per scenario with the
raddb, `radiusd.log`, `refused.log`, `normal.log` and `sink.log`.

A build without the change does not load this configuration (`Refused-Reason` is not in its
dictionary). Run against it with this branch's dictionaries (`DICTDIR=<dir>`), it ignores the
option: the `errors` rows and every row which expects a run of the refused server fail (against
`taranac-1.3.5`, 25 of the 55 cases; the `receive` scenario against the build without the
receive-path change, 18 of its 34). The `s_off` rows, the right-secret rows and the "no reply"
rows pass on any build: they guard against regressions, they are not evidence that the change
works.

## Scenarios

- `dictionary` — `Refused-Reason` is defined once, no other vendor-0 attribute in any installed
  dictionary has its number (a merge which adds one elsewhere would not conflict), and its
  values are those of `refused_reason_t`.
- `check` — `radiusd -XC` accepts the option on auth and acct listeners.
- `errors` — `radiusd -XC` refuses the option naming a server which does not exist, on a
  `status` listener, and on a TCP `auth` listener.
- `signature` — on 127.0.0.1 and on ::1:
  - radclient, wrong secret: an Access-Request (with Message-Authenticator) and an
    Accounting-Request get no reply; the refused server runs once with `Key-Mismatch`, the
    Packet-Type, User-Name, the server's error text and the source address, and without
    User-Password and Message-Authenticator; the daemon's log line is unchanged;
  - an Access-Request with User-Password, CHAP-Password, Tunnel-Password and
    MS-MPPE-Send-Key, and an Accounting-Request with Tunnel-Password: none of the
    secret-dependent attributes reaches the server, under its name or as an undecoded
    attribute; CHAP-Password does (it does not depend on the secret);
  - the same octets sent three times: three runs, no reply;
  - Status-Server: answered with the right secret (no run), refused with the wrong one;
  - the right secret: handled by `s_on` as before, the refused server does not run;
  - the refused server asks to proxy, to originate a CoA request, and accepts with a reply
    attribute: nothing is sent to the sinks and the client gets no reply; the controls show
    that the same policy in `s_on` does proxy and does send the CoA request;
  - `s_off`, without the option: dropped as before, with the daemon's log line, nothing runs.
- `malformed` — with `max_attributes = 4`, a correctly signed Accounting-Request and an
  Access-Request with a valid Message-Authenticator which carry three Cisco-AVPairs in one
  Vendor-Specific pass the header checks and fail to decode: one run each with
  `Malformed-Request`, the error text and no other attribute, no reply; the same within the
  limit is handled; on `s_off` nothing runs.

- `receive` — packets the receive path refuses, from clients `ma5` (127.0.0.5, requires
  Message-Authenticator), `lps9` (127.0.0.9, `limit_proxy_state`), an `identify_by` entry `sx`
  (127.0.66.1), `lo4`, and `lo6` (::1, requires Message-Authenticator here). Each probe is one
  second after the previous one, so that the daemon's rate limited line is there to compare:
  - no Message-Authenticator where the client, the `identify_by` entry, Status-Server,
    EAP-Message, or Proxy-State with `limit_proxy_state` requires one: one run with
    `Message-Authenticator-Missing`, the Packet-Type, User-Name and source, without
    User-Password or Tunnel-Password, and a Module-Failure-Message which is the daemon's
    "Ignoring request" line word for word (which names EAP-Message and Proxy-State apart);
  - Accounting-Request to the auth port, Access-Request to the acct port, code 99: one run with
    `Wrong-Port`, the attributes decoded without the secret-dependent ones;
  - malformed attributes behind a valid header (attribute too short, attribute 0, EAP-Message
    with User-Password): one run with `Malformed-Request` and no other attribute;
  - an invalid header (Length field below 20), and anything from an unknown source: no run, the
    daemon's line as before (none for the unknown source);
  - the same octets three times: three runs; valid requests from `lo4` and `ma5`: handled, no
    run; `s_off`: the daemon's line, no run; IPv6 on ::1: missing Message-Authenticator, both
    wrong ports, malformed;
  - a burst (`BURST`, default 500) of Access-Requests without Message-Authenticator from `ma5`,
    in a radiusd of its own in daemon mode with `max_requests = 1024` and 32 threads, 25 packets
    every 2.5 ms, while `lo4` sends valid requests one at a time: one run per packet radiusd read
    (the kernel's receive buffer errors are subtracted), every valid request answered within
    `BURST_BOUND_MS` (default 250), the daemon logs `ma5` once a second. The same burst
    unpaced, and to `s_off`, is measured and recorded, not judged.

Proxying is tested before the CoA request: radiusd 3.2.10 crashes, with or without this
option, when it proxies while a CoA request it originated is still unanswered.
