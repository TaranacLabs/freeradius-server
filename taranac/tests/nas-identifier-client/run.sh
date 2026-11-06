#!/bin/bash
# identify_by = nas_identifier harness: radiusd with identify_by clients, probed with radclient
# from several local source addresses.
#
#   run.sh <workdir> [scenario ...]        default: all (check errors main ratelimit drops stock)
#
# Needs in PATH (or RADIUSD=/path, RADCLIENT=/path): radiusd and radclient built from the ref
# under test, ip (iproute2 or busybox), and root with CAP_NET_ADMIN: the harness adds the source addresses
# below to "lo", so run it in a throwaway container:
#
#   docker run --rm --network none --cap-add NET_ADMIN \
#       --sysctl net.ipv6.conf.all.disable_ipv6=0 <image> run.sh /tmp/w
#
# A packet sent to a local address leaves from that address, so the address radclient sends
# to is the source address radiusd sees.
#
# Output: <workdir>/results.tsv (scenario, case, expected, actual, verdict),
#         <workdir>/summary.md, a directory per scenario with raddb, radiusd.log, probe logs.
# Exit:   0 all PASS, 1 any FAIL.
#
# Verdicts:
#   accept:<name>  - radclient gets Access-Accept AND Reply-Message (the server copies
#                    %{Client-Shortname} into it) is <name>.  The password check proves that
#                    User-Password was decrypted with the secret of that entry, and radclient
#                    checks the reply authenticator with the secret it sent with.
#   acct:<name>    - Accounting-Response with Reply-Message <name>.
#   status         - Access-Accept to Status-Server.
#   reject         - Access-Reject.
#   drop:<regex>   - no reply AND the probe's slice of the server log matches <regex>.
#   config error   - "radiusd -XC" fails AND its output matches the expected message.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: run.sh <workdir> [scenario ...]}
shift
mkdir -p "$W"
W=$(cd "$W" && pwd)
RADIUSD=${RADIUSD:-radiusd}
RADCLIENT=${RADCLIENT:-radclient}
DICTDIR=${DICTDIR:-/usr/share/freeradius}
LIBDIR=${LIBDIR:-/usr/lib/freeradius}
SCEN=${*:-check errors main ratelimit drops stock}

V4_SOURCES="10.77.0.1 10.77.0.5 10.77.0.9 10.66.0.1 10.66.0.2 10.55.0.1 10.88.0.1"
V6_SOURCES="fd00:77::1"

RESULTS=$W/results.tsv
printf 'scenario\tcase\texpected\tactual\tverdict\n' >"$RESULTS"
FAILS=0

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

record() {	# scenario case expected actual verdict
	printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RESULTS"
	[ "$5" = PASS ] || FAILS=$((FAILS + 1))
	printf '  %-4s %-9s %-58s %s\n' "$5" "$1" "$2" "${4:0:80}"
}

setup_addresses() {
	local a
	for a in $V4_SOURCES; do ip addr add "$a/32" dev lo 2>/dev/null; done
	for a in $V6_SOURCES; do
		ip -6 addr add "$a/128" dev lo nodad 2>/dev/null || ip -6 addr add "$a/128" dev lo 2>/dev/null
	done
	ip addr show dev lo | grep -q 'inet 10.77.0.1/' || { echo "cannot add addresses to lo (CAP_NET_ADMIN?)"; exit 1; }
	ip -6 addr show dev lo | grep -q 'fd00:77::1' || { echo "cannot add IPv6 addresses to lo (disable_ipv6?)"; exit 1; }
}

# raddb <dir> <clients.conf body>
raddb() {
	local d=$1
	mkdir -p "$d/run"
	cat >"$d/radiusd.conf" <<CONF
prefix = /usr
raddbdir = $d
confdir = $d
run_dir = $d/run
logdir = $d
libdir = $LIBDIR
pidfile = $d/run/radiusd.pid
max_request_time = 5
cleanup_delay = 0
hostname_lookups = no
security {
	allow_core_dumps = no
	status_server = yes
	require_message_authenticator = no
	limit_proxy_state = no
}
log {
	destination = files
	file = $d/radiusd.log
}
thread pool {
	start_servers = 2
	max_servers = 4
	min_spare_servers = 1
	max_spare_servers = 4
}
modules {
	always ok {
		rcode = ok
	}
}
\$INCLUDE clients.conf
server default {
	listen {
		type = auth
		ipaddr = *
		port = 1812
	}
	listen {
		type = acct
		ipaddr = *
		port = 1813
	}
	listen {
		type = auth
		ipv6addr = ::
		port = 1812
	}
	listen {
		type = acct
		ipv6addr = ::
		port = 1813
	}
	authorize {
		update reply {
			&Reply-Message := "%{Client-Shortname}"
		}
		if (&User-Password == "pw") {
			update control {
				&Auth-Type := Accept
			}
		}
		else {
			update control {
				&Auth-Type := Reject
			}
		}
	}
	accounting {
		update reply {
			&Reply-Message := "%{Client-Shortname}"
		}
		ok
	}
}
server other {
	authorize {
		update reply {
			&Reply-Message := "other:%{Client-Shortname}"
		}
		update control {
			&Auth-Type := Accept
		}
	}
}
CONF
	printf '%s\n' "$2" >"$d/clients.conf"
}

PID=
start() {	# <dir> [extra radiusd flags, default -fxx]
	local d=$1 flags=${2:--fxx} i
	: >"$d/radiusd.log"
	"$RADIUSD" $flags -d "$d" -D "$DICTDIR" -l "$d/radiusd.log" >"$d/stdout.log" 2>&1 &
	PID=$!
	for i in $(seq 1 100); do
		grep -q 'Ready to process requests' "$d/radiusd.log" "$d/stdout.log" 2>/dev/null && return 0
		kill -0 "$PID" 2>/dev/null || break
		sleep 0.1
	done
	# daemon mode does not log "Ready": probe the localhost client instead
	if kill -0 "$PID" 2>/dev/null; then
		for i in $(seq 1 50); do
			echo 'User-Name = "probe", User-Password = "pw"' |
				"$RADCLIENT" -D "$DICTDIR" -t 1 -r 1 127.0.0.1:1812 auth testing123 >/dev/null 2>&1 && return 0
			sleep 0.1
		done
	fi
	echo "radiusd did not start:"; tail -20 "$d/radiusd.log" "$d/stdout.log"
	return 1
}

stop() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	PID=
}

# probe <scenario> <dir> <case> <expected> <server> <type> <secret> <attrs...>
#   expected: accept:<name> | acct:<name> | status | reject | drop:<regex>
probe() {
	local s=$1 d=$2 c=$3 exp=$4 server=$5 type=$6 secret=$7
	shift 7
	local n out actual slice ok=FAIL
	n=$(wc -l <"$d/radiusd.log")
	out=$d/probe-$(echo "$c" | tr -c 'A-Za-z0-9\n' '_').log
	printf '%s\n' "$@" | paste -sd, - |
		"$RADCLIENT" -x -D "$DICTDIR" -t 1 -r 1 "$server" "$type" "$secret" >"$out" 2>&1
	sleep 0.3
	slice=$(tail -n +"$((n + 1))" "$d/radiusd.log")
	printf '%s\n' "--- server log ---" "$slice" >>"$out"

	if grep -q 'Received Access-Accept' "$out"; then
		actual="accept:$(sed -n 's/^.*Reply-Message = "\(.*\)"$/\1/p' "$out" | head -1)"
	elif grep -q 'Received Accounting-Response' "$out"; then
		actual="acct:$(sed -n 's/^.*Reply-Message = "\(.*\)"$/\1/p' "$out" | head -1)"
	elif grep -q 'Received Access-Reject' "$out"; then
		actual=reject
	elif grep -q 'No reply from server' "$out"; then
		actual=drop
	else
		actual="other: $(grep -v '^Sent\|^\s' "$out" | head -1)"
	fi

	case "$exp" in
	drop:*)
		if [ "$actual" = drop ]; then
			if printf '%s\n' "$slice" | grep -Eq "${exp#drop:}"; then ok=PASS; else actual="drop, log lacks: ${exp#drop:}"; fi
		fi
		;;
	status)
		[ "${actual%%:*}" = accept ] && [ "$type" = status ] && ok=PASS
		;;
	*)
		[ "$actual" = "$exp" ] && ok=PASS
		;;
	esac
	record "$s" "$c" "$exp" "$actual" "$ok"
}

MA_OFF='Message-Authenticator !* ANY'

CLIENTS_MAIN='
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
	shortname = localhost
}
client plain5 {
	ipaddr = 10.77.0.5
	secret = plain5-secret
	shortname = plain5
}
client plain16 {
	ipaddr = 10.77.0.0/16
	secret = plain16-secret
	shortname = plain16
}
client site77 {
	ipaddr = 10.77.0.0/24
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "secret-a-77"
		shortname = "sa"
	}
	nas_identifier "b" {
		secret = "secret-b-77"
		shortname = "sb"
	}
	nas_identifier "vs" {
		secret = "secret-vs-77"
		shortname = "svs"
		virtual_server = other
	}
}
client site66 {
	ipaddr = 10.66.0.0/24
	identify_by = nas_identifier
	nas_identifier "x" {
		secret = "secret-x-66"
		shortname = "sx"
	}
}
client site55 {
	ipaddr = 10.55.0.0/24
	identify_by = nas_identifier
	secret = "fallback-55"
	shortname = "fb55"
	nas_identifier "c" {
		secret = "secret-c-55"
		shortname = "sc"
	}
}
client any4 {
	ipaddr = 0.0.0.0/0
	identify_by = nas_identifier
	nas_identifier "anywhere" {
		secret = "secret-any4"
		shortname = "any4"
	}
	nas_identifier "a" {
		secret = "secret-a-any"
		shortname = "a-any"
	}
}
client any6 {
	ipv6addr = ::/0
	identify_by = nas_identifier
	nas_identifier "anywhere" {
		secret = "secret-any6"
		shortname = "any6"
	}
}
client site6 {
	ipv6addr = fd00:77::/64
	identify_by = nas_identifier
	nas_identifier "v6a" {
		secret = "secret-v6a"
		shortname = "v6a"
	}
}
'

U='User-Name = "u"'
P='User-Password = "pw"'

scenario_check() {
	local s=check d=$W/check out
	raddb "$d" "$CLIENTS_MAIN"
	out=$d/check.log
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$out" 2>&1; then
		record $s "radiusd -XC" "ok" "ok" PASS
	else
		record $s "radiusd -XC" "ok" "fails: $(grep -i error "$out" | head -1)" FAIL
	fi
	local m
	for m in 'client site77: identify_by nas_identifier: 3 entries$' \
		 'client site66: identify_by nas_identifier: 1 entries$' \
		 'client site55: identify_by nas_identifier: 1 entries, other packets use the client secret$' \
		 'client any4: identify_by nas_identifier: 2 entries$' \
		 'client any6: identify_by nas_identifier: 1 entries$' \
		 'client site6: identify_by nas_identifier: 1 entries$'; do
		if grep -Eq "$m" "$out"; then
			record $s "marker ${m%%:*}" "line" "line" PASS
		else
			record $s "marker ${m%%:*}" "line" "missing" FAIL
		fi
	done
}

# config_error <case> <regex> <clients.conf body>
config_error() {
	local s=errors d out
	d=$W/errors/$(echo "$1" | tr -c 'A-Za-z0-9\n' '_')
	raddb "$d" "$3"
	out=$d/check.log
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$out" 2>&1; then
		record $s "$1" "error: $2" "accepted" FAIL
	elif grep -Eq "$2" "$out"; then
		record $s "$1" "error: $2" "error" PASS
	else
		record $s "$1" "error: $2" "other error: $(grep -iE 'error|fail' "$out" | head -1)" FAIL
	fi
}

scenario_errors() {
	config_error "nas_identifier without identify_by" '"nas_identifier" needs "identify_by = nas_identifier"' '
client c1 {
	ipaddr = 10.1.0.0/24
	secret = s3cret-s3cret
	nas_identifier "a" {
		secret = "x"
	}
}'
	config_error "identify_by = foo" 'Invalid value for "identify_by"' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = foo
	nas_identifier "a" {
		secret = "x"
	}
}'
	config_error "proto = tcp" 'needs "proto = udp"' '
client c1 {
	ipaddr = 10.1.0.0/24
	proto = tcp
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "x"
	}
}'
	config_error "entry require_message_authenticator = no" 'cannot be anything but "yes"' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "x"
		require_message_authenticator = no
	}
}'
	config_error "duplicate entry" 'Duplicate nas_identifier "a"' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "x"
	}
	nas_identifier "a" {
		secret = "y"
	}
}'
	config_error "entry without secret" 'nas_identifier "a": secret must be at least 1 character long' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	nas_identifier "a" {
		shortname = "x"
	}
}'
	config_error "identify_by without entries" 'needs at least one "nas_identifier" subsection' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
}'
	config_error "empty nas_identifier" 'nas_identifier must have a non-empty value' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	nas_identifier "" {
		secret = "x"
	}
}'
	config_error "unknown virtual_server" 'virtual server nosuch does not exist' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "x"
		virtual_server = nosuch
	}
}'
	config_error "two identify_by clients, one prefix" 'Failed to add duplicate client' '
client c1 {
	ipaddr = 0.0.0.0/0
	identify_by = nas_identifier
	nas_identifier "a" {
		secret = "x"
	}
}
client c2 {
	ipaddr = 0.0.0.0/0
	identify_by = nas_identifier
	nas_identifier "b" {
		secret = "y"
	}
}'
	config_error "tls subsection" 'cannot be used with "tls"' '
client c1 {
	ipaddr = 10.1.0.0/24
	identify_by = nas_identifier
	tls {
	}
	nas_identifier "a" {
		secret = "x"
	}
}'
}

scenario_main() {
	local s=main d=$W/main
	raddb "$d" "$CLIENTS_MAIN"
	start "$d" || { record $s start ok failed FAIL; return; }

	# selection by NAS-Identifier, two entries behind one address
	probe $s "$d" "right secret by NAS-ID (a)"            accept:sa  10.77.0.1:1812 auth secret-a-77 "$U" "$P" 'NAS-Identifier = "a"'
	probe $s "$d" "second NAS-ID, same address (b)"       accept:sb  10.77.0.1:1812 auth secret-b-77 "$U" "$P" 'NAS-Identifier = "b"'
	probe $s "$d" "wrong password -> reject (decrypted)"   reject     10.77.0.1:1812 auth secret-a-77 "$U" 'User-Password = "bad"' 'NAS-Identifier = "a"'
	probe $s "$d" "NAS-ID a with b's secret"              'drop:invalid Message-Authenticator' 10.77.0.1:1812 auth secret-b-77 "$U" "$P" 'NAS-Identifier = "a"'
	probe $s "$d" "missing Message-Authenticator"         'drop:does not contain required Message-Authenticator' 10.77.0.1:1812 auth secret-a-77 "$U" "$P" 'NAS-Identifier = "a"' "$MA_OFF"
	probe $s "$d" "entry virtual_server"                  accept:other:svs 10.77.0.1:1812 auth secret-vs-77 "$U" "$P" 'NAS-Identifier = "vs"'

	# unknown / missing / repeated NAS-Identifier, no address client covers the source
	probe $s "$d" "unknown NAS-ID"                        'drop:NAS-Identifier "zzz" matches no nas_identifier of client site66' 10.66.0.1:1812 auth secret-x-66 "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "missing NAS-ID"                        'drop:no NAS-Identifier, which client site66 needs' 10.66.0.1:1812 auth secret-x-66 "$U" "$P"
	probe $s "$d" "two NAS-Identifier attributes"         'drop:2 NAS-Identifier attributes, client site66 needs exactly one' 10.66.0.1:1812 auth secret-x-66 "$U" "$P" 'NAS-Identifier = "x"' 'NAS-Identifier += "x"'
	probe $s "$d" "control: same source, known NAS-ID"    accept:sx  10.66.0.1:1812 auth secret-x-66 "$U" "$P" 'NAS-Identifier = "x"'
	probe $s "$d" "unknown NAS-ID, escaped in the log"    'drop:NAS-Identifier "q\\"z\\001" matches no' 10.66.0.1:1812 auth secret-x-66 "$U" "$P" 'NAS-Identifier = "q\"z\001"'

	# any source (0.0.0.0/0) and longest prefix among identify_by clients
	probe $s "$d" "any-source client"                     accept:any4  10.88.0.1:1812 auth secret-any4  "$U" "$P" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "any-source, other address"             accept:any4  10.66.0.1:1812 auth secret-any4  "$U" "$P" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "any-source, unknown NAS-ID"            'drop:NAS-Identifier "zzz" matches no nas_identifier of client any4' 10.88.0.1:1812 auth secret-any4 "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "NAS-ID a outside site77 -> any4 entry" accept:a-any 10.88.0.1:1812 auth secret-a-any "$U" "$P" 'NAS-Identifier = "a"'
	probe $s "$d" "NAS-ID a inside site77 -> longest"     'drop:invalid Message-Authenticator' 10.77.0.1:1812 auth secret-a-any "$U" "$P" 'NAS-Identifier = "a"'

	# precedence against address clients
	probe $s "$d" "entry beats exact address client"      accept:sa     10.77.0.5:1812 auth secret-a-77    "$U" "$P" 'NAS-Identifier = "a"'
	probe $s "$d" "no entry -> exact address client"      accept:plain5 10.77.0.5:1812 auth plain5-secret  "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "no NAS-ID -> exact address client"     accept:plain5 10.77.0.5:1812 auth plain5-secret  "$U" "$P"
	probe $s "$d" "no entry -> shorter plain (/16)"       accept:plain16 10.77.0.9:1812 auth plain16-secret "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "entry inside plain /16"                accept:sb     10.77.0.9:1812 auth secret-b-77    "$U" "$P" 'NAS-Identifier = "b"'
	probe $s "$d" "plain client, no MA (stock)"           accept:plain16 10.77.0.9:1812 auth plain16-secret "$U" "$P" "$MA_OFF"
	probe $s "$d" "entry beats localhost /32"             accept:any4   127.0.0.1:1812 auth secret-any4    "$U" "$P" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "localhost without NAS-ID"              accept:localhost 127.0.0.1:1812 auth testing123  "$U" "$P"

	# identify_by client with a secret of its own
	probe $s "$d" "fallback client: entry"                accept:sc   10.55.0.1:1812 auth secret-c-55 "$U" "$P" 'NAS-Identifier = "c"'
	probe $s "$d" "fallback client: unknown NAS-ID"       accept:fb55 10.55.0.1:1812 auth fallback-55 "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "fallback client: no NAS-ID"            accept:fb55 10.55.0.1:1812 auth fallback-55 "$U" "$P"
	probe $s "$d" "fallback client: entry, client secret" 'drop:invalid Message-Authenticator' 10.55.0.1:1812 auth fallback-55 "$U" "$P" 'NAS-Identifier = "c"'

	# IPv6
	probe $s "$d" "IPv6 entry"                            accept:v6a  '[fd00:77::1]:1812' auth secret-v6a  "$U" "$P" 'NAS-Identifier = "v6a"'
	probe $s "$d" "IPv6 any source (::1)"                 accept:any6 '[::1]:1812'        auth secret-any6 "$U" "$P" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "IPv6 /64 without entry -> ::/0 entry"  accept:any6 '[fd00:77::1]:1812' auth secret-any6 "$U" "$P" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "IPv6 unknown NAS-ID"                   'drop:NAS-Identifier "zzz" matches no nas_identifier of client site6' '[fd00:77::1]:1812' auth secret-v6a "$U" "$P" 'NAS-Identifier = "zzz"'
	probe $s "$d" "IPv4 entry not used for IPv6"          'drop:NAS-Identifier "a" matches no nas_identifier of client any6' '[::1]:1812' auth secret-a-any "$U" "$P" 'NAS-Identifier = "a"'

	# accounting: verified by the Request Authenticator, Message-Authenticator not needed
	local A='Acct-Status-Type = Start' S='Acct-Session-Id = "s1"'
	probe $s "$d" "acct: right secret by NAS-ID"          acct:sa  10.77.0.1:1813 acct secret-a-77 "$U" "$A" "$S" 'NAS-Identifier = "a"'
	probe $s "$d" "acct: second NAS-ID, same address"     acct:sb  10.77.0.1:1813 acct secret-b-77 "$U" "$A" "$S" 'NAS-Identifier = "b"' "$MA_OFF"
	probe $s "$d" "acct: wrong secret"                    'drop:invalid Request Authenticator' 10.77.0.1:1813 acct secret-b-77 "$U" "$A" "$S" 'NAS-Identifier = "a"'
	probe $s "$d" "acct: unknown NAS-ID"                  'drop:NAS-Identifier "zzz" matches no nas_identifier of client site66' 10.66.0.1:1813 acct secret-x-66 "$U" "$A" "$S" 'NAS-Identifier = "zzz"'
	probe $s "$d" "acct: missing NAS-ID"                  'drop:no NAS-Identifier, which client site66 needs' 10.66.0.1:1813 acct secret-x-66 "$U" "$A" "$S"
	probe $s "$d" "acct: any source"                      acct:any4 10.88.0.1:1813 acct secret-any4 "$U" "$A" "$S" 'NAS-Identifier = "anywhere"'
	probe $s "$d" "acct: IPv6 entry"                      acct:v6a '[fd00:77::1]:1813' acct secret-v6a "$U" "$A" "$S" 'NAS-Identifier = "v6a"'
	probe $s "$d" "acct: no entry -> exact address"       acct:plain5 10.77.0.5:1813 acct plain5-secret "$U" "$A" "$S" 'NAS-Identifier = "zzz"'

	# Status-Server to an entry
	probe $s "$d" "Status-Server by NAS-ID"               status   10.77.0.1:1812 status secret-a-77 'NAS-Identifier = "a"'
	probe $s "$d" "Status-Server, wrong secret"           'drop:invalid Message-Authenticator' 10.77.0.1:1812 status secret-b-77 'NAS-Identifier = "a"'

	stop
}

scenario_ratelimit() {
	local s=ratelimit d=$W/ratelimit i n1 n2 f p1 p2
	raddb "$d" "$CLIENTS_MAIN"
	start "$d" "-f" || { record $s start ok failed FAIL; return; }
	f=$d/burst.txt
	: >"$f"
	for i in $(seq 1 20); do printf '%s, %s, NAS-Identifier = "zzz"\n\n' "$U" "$P" >>"$f"; done
	"$RADCLIENT" -D "$DICTDIR" -t 1 -r 1 -p 20 -f "$f" 10.66.0.1:1812 auth secret-x-66 >/dev/null 2>&1 &
	p1=$!
	"$RADCLIENT" -D "$DICTDIR" -t 1 -r 1 -p 20 -f "$f" 10.66.0.2:1812 auth secret-x-66 >/dev/null 2>&1 &
	p2=$!
	wait "$p1" "$p2" 2>/dev/null
	sleep 0.3
	n1=$(grep -c 'from client 10.66.0.1 port .*matches no nas_identifier' "$d/radiusd.log")
	n2=$(grep -c 'from client 10.66.0.2 port .*matches no nas_identifier' "$d/radiusd.log")
	# 20 packets in well under 2 s: one line, two if the burst crosses a second
	if [ "$n1" -ge 1 ] && [ "$n1" -le 2 ]; then
		record $s "20 drops from one source, daemon mode" "1-2 lines" "$n1 lines" PASS
	else
		record $s "20 drops from one source, daemon mode" "1-2 lines" "$n1 lines" FAIL
	fi
	if [ "$n2" -ge 1 ] && [ "$n2" -le 2 ]; then
		record $s "second source logged on its own" "1-2 lines" "$n2 lines" PASS
	else
		record $s "second source logged on its own" "1-2 lines" "$n2 lines" FAIL
	fi
	stop
}

# Without identify_by clients the receive path is the upstream one.
scenario_stock() {
	local s=stock d=$W/stock
	raddb "$d" '
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
	shortname = localhost
}
client net77 {
	ipaddr = 10.77.0.0/24
	secret = net77-secret
	shortname = net77
}'
	start "$d" || { record $s start ok failed FAIL; return; }
	probe $s "$d" "address client"                accept:net77 10.77.0.1:1812 auth net77-secret "$U" "$P" 'NAS-Identifier = "a"'
	probe $s "$d" "address client, acct"          acct:net77   10.77.0.1:1813 acct net77-secret "$U" 'Acct-Status-Type = Start' 'NAS-Identifier = "a"'
	probe $s "$d" "unknown source [regression]"   'drop:unknown client 10.66.0.1' 10.66.0.1:1812 auth secret-x-66 "$U" "$P" 'NAS-Identifier = "x"'
	stop
}

# Drops which radiusd used to log only in debug mode: daemon mode (-f) must log them too, one
# "Ignoring request ..." line per source and second, with the client and never the User-Name.
CLIENTS_DROPS='
client localhost {
	ipaddr = 127.0.0.1
	secret = testing123
	shortname = localhost
}
client ma5 {
	ipaddr = 10.77.0.5
	secret = ma5-secret
	shortname = ma5
	require_message_authenticator = yes
}
client lps9 {
	ipaddr = 10.77.0.9
	secret = lps9-secret
	shortname = lps9
	require_message_authenticator = no
	limit_proxy_state = yes
}
client p88 {
	ipaddr = 10.88.0.1
	secret = p88-secret
	shortname = p88
}
client p6 {
	ipv6addr = fd00:77::1
	secret = p6-secret
	shortname = p6
}
client site66 {
	ipaddr = 10.66.0.0/24
	identify_by = nas_identifier
	nas_identifier "x" {
		secret = "secret-x-66"
		shortname = "sx"
	}
}
'

# raw <host> <port> <hex bytes...>: one UDP datagram (bash's /dev/udp); the host is a local
# address, so it is also the source address radiusd sees.  The bytes go through a file and dd
# (one read, one write): printf straight to the socket flushes at every 0x0a and would split the
# datagram, and busybox cat sends nothing to an IPv6 /dev/udp socket.
raw() {
	local host=$1 port=$2 b fmt=
	shift 2
	for b in "$@"; do fmt="$fmt\\x$b"; done
	printf "$fmt" >"$W/raw.bin"
	dd if="$W/raw.bin" bs=4096 2>/dev/null >"/dev/udp/$host/$port"
}

AUTH16='00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'

# raw_drop <scenario> <dir> <case> <regex|-> <host> <port> <hex...>
#   regex: the probe's slice of the log must match it; "-": no "Ignoring request" line at all.
raw_drop() {
	local s=$1 d=$2 c=$3 re=$4 host=$5 port=$6 n slice
	shift 6
	n=$(wc -l <"$d/radiusd.log")
	raw "$host" "$port" "$@"
	sleep 0.3
	slice=$(tail -n +"$((n + 1))" "$d/radiusd.log")
	printf '%s\n' "$slice" >"$d/probe-$(echo "$c" | tr -c 'A-Za-z0-9\n' '_').log"
	if [ "$re" = - ]; then
		if printf '%s\n' "$slice" | grep -q 'Ignoring request'; then
			record "$s" "$c" "no line" "$(printf '%s\n' "$slice" | grep 'Ignoring request' | head -1)" FAIL
		else
			record "$s" "$c" "no line" "no line" PASS
		fi
	elif printf '%s\n' "$slice" | grep -Eq "$re"; then
		record "$s" "$c" "line: $re" "line" PASS
	else
		record "$s" "$c" "line: $re" "log lacks it: $(printf '%s\n' "$slice" | head -1)" FAIL
	fi
}

scenario_drops() {
	local s=drops d=$W/drops i n
	local UN='User-Name = "drop-user-7x"' A='Acct-Status-Type = Start'
	local PFX='^.* : Error: Ignoring request to (auth|acct) address [^ ]+ port 181[23]( bound to server [a-z]+)? from client'
	raddb "$d" "$CLIENTS_DROPS"
	start "$d" "-f" || { record $s start ok failed FAIL; return; }

	# one second between probes: every case below would otherwise hit the per-source limit
	sleep 1.1
	probe $s "$d" "no MA, require_message_authenticator"  "drop:$PFX 10.77.0.5 port [0-9]+: no Message-Authenticator, which client ma5 requires\$" 10.77.0.5:1812 auth ma5-secret "$UN" "$P" "$MA_OFF"
	sleep 1.1
	probe $s "$d" "no MA, NAS-Identifier entry"           "drop:$PFX 10.66.0.1 port [0-9]+: no Message-Authenticator, which client sx requires\$" 10.66.0.1:1812 auth secret-x-66 "$UN" "$P" 'NAS-Identifier = "x"' "$MA_OFF"
	sleep 1.1
	probe $s "$d" "Proxy-State, no MA, limit_proxy_state" "drop:$PFX 10.77.0.9 port [0-9]+: Proxy-State without Message-Authenticator, which client lps9 refuses \\(limit_proxy_state\\)\$" 10.77.0.9:1812 auth lps9-secret "$UN" "$P" 'Proxy-State = 0x01' "$MA_OFF"
	sleep 1.1
	probe $s "$d" "Status-Server without MA"              "drop:$PFX 10.88.0.1 port [0-9]+: Status-Server without Message-Authenticator, client p88\$" 10.88.0.1:1812 status p88-secret "$MA_OFF"
	sleep 1.1
	probe $s "$d" "control: no MA, plain client"          accept:p88 10.88.0.1:1812 auth p88-secret "$UN" "$P" "$MA_OFF"
	sleep 1.1
	probe $s "$d" "Accounting-Request to auth port"       "drop:$PFX 10.88.0.1 port [0-9]+: packet code 4 \\(Accounting-Request\\) is not accepted here, client p88\$" 10.88.0.1:1812 acct p88-secret "$UN" "$A"
	sleep 1.1
	probe $s "$d" "Access-Request to acct port"           "drop:$PFX 10.88.0.1 port [0-9]+: packet code 1 \\(Access-Request\\) is not accepted here, client p88\$" 10.88.0.1:1813 auth p88-secret "$UN" "$P"
	sleep 1.1
	raw_drop $s "$d" "unknown code 99 to auth port"       "$PFX 10.88.0.1 port [0-9]+: packet code 99 \\(unknown\\) is not accepted here, client p88\$" 10.88.0.1 1812 63 01 00 14 $AUTH16
	sleep 1.1
	raw_drop $s "$d" "attribute too short"                "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(attribute too short\\), client p88\$" 10.88.0.1 1812 01 02 00 18 $AUTH16 01 01 00 00
	sleep 1.1
	raw_drop $s "$d" "acct: attribute 0"                  "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(attribute 0\\), client p88\$" 10.88.0.1 1813 04 03 00 18 $AUTH16 00 04 41 41
	sleep 1.1
	raw_drop $s "$d" "attribute header overflow"          "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(attribute header overflows the packet\\), client p88\$" 10.88.0.1 1812 01 04 00 15 $AUTH16 01
	sleep 1.1
	raw_drop $s "$d" "datagram shorter than Length"       "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(shorter than its Length field\\), client p88\$" 10.88.0.1 1812 01 05 00 64 $AUTH16 01 04 41 41
	sleep 1.1
	raw_drop $s "$d" "Length field < 20"                  "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(invalid header\\), client p88\$" 10.88.0.1 1812 01 06 00 0b 00 00 00 00 00 00 00
	sleep 1.1
	raw_drop $s "$d" "3-byte datagram"                    "$PFX 10.88.0.1 port [0-9]+: malformed packet \\(invalid header\\), client p88\$" 10.88.0.1 1812 01 07 00
	sleep 1.1
	raw_drop $s "$d" "IPv6: attribute too short"          "$PFX fd00:77::1 port [0-9]+: malformed packet \\(attribute too short\\), client p6\$" fd00:77::1 1812 01 08 00 18 $AUTH16 01 01 00 00
	sleep 1.1
	raw_drop $s "$d" "identify_by source: invalid header" "$PFX 10.66.0.1 port [0-9]+: malformed packet \\(invalid header\\), client site66\$" 10.66.0.1 1812 01 09 00 0b 00 00 00 00 00 00 00
	sleep 1.1
	raw_drop $s "$d" "identify_by source: bad attribute"  "$PFX 10.66.0.1 port [0-9]+: malformed packet\$" 10.66.0.1 1812 01 0c 00 18 $AUTH16 01 01 00 00
	sleep 1.1
	raw_drop $s "$d" "unknown source, bad header: no line" - 10.55.0.1 1812 01 0b 00 0b 00 00 00 00 00 00 00

	# rate limit: 20 malformed packets from one source in a burst, one line (two if the burst
	# crosses a second); the limiter is shared with the NAS-Identifier lines
	sleep 1.1
	n=$(grep -c 'from client 10.88.0.1 port .*: malformed packet' "$d/radiusd.log")
	for i in $(seq 1 20); do raw 10.88.0.1 1812 01 0d 00 18 $AUTH16 01 01 00 00; done
	sleep 0.3
	n=$(($(grep -c 'from client 10.88.0.1 port .*: malformed packet' "$d/radiusd.log") - n))
	if [ "$n" -ge 1 ] && [ "$n" -le 2 ]; then
		record $s "20 drops from one source, one line" "1-2 lines" "$n lines" PASS
	else
		record $s "20 drops from one source, one line" "1-2 lines" "$n lines" FAIL
	fi

	if grep -q 'drop-user-7x' "$d/radiusd.log"; then
		record $s "User-Name never logged" "absent" "present" FAIL
	else
		record $s "User-Name never logged" "absent" "absent" PASS
	fi
	stop
}

trap stop EXIT
setup_addresses
say "radiusd: $("$RADIUSD" -v | head -1)"
for sc in $SCEN; do
	say "scenario $sc"
	"scenario_$sc"
done

{
	echo "# identify_by = nas_identifier harness"
	echo
	echo "radiusd: \`$("$RADIUSD" -v | head -1)\`"
	echo
	echo "| scenario | case | expected | actual | verdict |"
	echo "|---|---|---|---|---|"
	tail -n +2 "$RESULTS" | sed 's/|/\\|/g; s/\t/ | /g; s/^/| /; s/$/ |/'
	echo
	echo "Total: $(($(wc -l <"$RESULTS") - 1)) cases, $FAILS failed."
} >"$W/summary.md"
say "$(($(wc -l <"$RESULTS") - 1)) cases, $FAILS failed"
[ "$FAILS" = 0 ]
