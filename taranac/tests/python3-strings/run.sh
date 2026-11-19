#!/bin/bash
# rlm_python3 "unicode_errors" harness: radiusd with python3 instances that differ only in
# unicode_errors, probed with radclient and with raw datagrams on 127.0.0.1.
#
#   run.sh <workdir> [scenario ...]        default: all (check errors main)
#
# Needs in PATH (or RADIUSD=/path, RADCLIENT=/path): radiusd and radclient built from the ref
# under test with rlm_python3, python3, bash and od.  No extra addresses and no capabilities:
#
#   docker run --rm --network none <image> run.sh /tmp/w
#
# Output: <workdir>/results.tsv (scenario, case, expected, actual, verdict),
#         <workdir>/summary.md, a directory per scenario with raddb, radiusd.log, probe logs,
#         and seen.tsv (one line per call of the Python function).
# Exit:   0 all PASS, 1 any FAIL.
#
# Verdicts:
#   value:<repr>    - the Python function was called, and ascii() of the attribute it got is
#                     <repr> (U+FFFD shows as \ufffd, a NUL would show as \x00).
#   fail            - the function was not called and the probe's slice of the server log has
#                     "mod_populate_vps failed".
#   batch:<rule>    - a series of 20 radclient requests; see scenario_main.
#   config error    - "radiusd -XC" fails AND its output names the bad value.
set -u
W=${1:?usage: run.sh <workdir> [scenario ...]}
shift
mkdir -p "$W"
W=$(cd "$W" && pwd)
RADIUSD=${RADIUSD:-radiusd}
RADCLIENT=${RADCLIENT:-radclient}
DICTDIR=${DICTDIR:-/usr/share/freeradius}
LIBDIR=${LIBDIR:-/usr/lib/freeradius}
SCEN=${*:-check errors main}

RESULTS=$W/results.tsv
printf 'scenario\tcase\texpected\tactual\tverdict\n' >"$RESULTS"
FAILS=0

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

record() {	# scenario case expected actual verdict
	printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RESULTS"
	[ "$5" = PASS ] || FAILS=$((FAILS + 1))
	printf '  %-4s %-7s %-52s %s\n' "$5" "$1" "$2" "${4:0:80}"
}

# One python3 instance and one auth port per handler.  "default" has no unicode_errors line.
HANDLERS="default replace ignore backslashreplace"
port_of() {
	case $1 in
	default) echo 1812 ;;
	replace) echo 1822 ;;
	ignore) echo 1832 ;;
	backslashreplace) echo 1842 ;;
	esac
}

# raddb <dir> [unicode_errors value for every instance but "default", may be empty; without it
#              each instance gets its own name]
raddb() {
	local d=$1 forced=${2-} forced_set=${2+set} h ue
	mkdir -p "$d/run" "$d/py"
	: >"$d/seen.tsv"
	# The function writes: instance, NAS-Identifier (the probe's case tag), ascii(User-Name),
	# ascii(User-Password), and "nul" if any request value holds a NUL.
	cat >"$d/py/probe.py" <<PY
OUT = "$d/seen.tsv"


def make(tag):
    def authorize(p):
        d = dict(p)
        nul = any("\\x00" in v for k, v in p)
        with open(OUT, "a") as f:
            f.write("%s\\t%s\\t%s\\t%s\\t%s\\n" % (tag, d.get("NAS-Identifier", "-"),
                    ascii(d.get("User-Name")), ascii(d.get("User-Password")),
                    "nul" if nul else "-"))
        return 2  # RLM_MODULE_OK
    return authorize
PY
	{
		cat <<CONF
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
client localhost {
	ipaddr = 127.0.0.1
	secret = right
	require_message_authenticator = no
	limit_proxy_state = no
}
modules {
CONF
		for h in $HANDLERS; do
			printf 'from probe import make\nauthorize = make("%s")\n' "$h" >"$d/py/p_$h.py"
			ue=$h
			[ -n "$forced_set" ] && ue=$forced
			printf '\tpython3 py_%s {\n\t\tpython_path = "%s"\n\t\tmodule = p_%s\n' "$h" "$d/py" "$h"
			printf '\t\tmod_authorize = ${.module}\n\t\tfunc_authorize = authorize\n'
			[ "$h" = default ] || printf '\t\tunicode_errors = "%s"\n' "$ue"
			printf '\t}\n'
		done
		echo '}'
		for h in $HANDLERS; do
			cat <<CONF
server s_$h {
	listen {
		type = auth
		ipaddr = 127.0.0.1
		port = $(port_of "$h")
	}
	authorize {
		py_$h
		update control {
			&Auth-Type := Reject
		}
	}
	authenticate {
	}
}
CONF
		done
	} >"$d/radiusd.conf"
}

PID=
start() {	# <dir>
	local d=$1 i
	: >"$d/radiusd.log"
	"$RADIUSD" -fxx -d "$d" -D "$DICTDIR" -l "$d/radiusd.log" >"$d/stdout.log" 2>&1 &
	PID=$!
	for i in $(seq 1 100); do
		grep -q 'Ready to process requests' "$d/radiusd.log" "$d/stdout.log" 2>/dev/null && return 0
		kill -0 "$PID" 2>/dev/null || break
		sleep 0.1
	done
	echo "radiusd did not start:"; tail -20 "$d/radiusd.log" "$d/stdout.log"
	return 1
}

stop() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	PID=
}

hex() { printf '%s' "$1" | od -An -v -tx1; }

# raw <port> <hex bytes...>: one UDP datagram from 127.0.0.1 (bash's /dev/udp), through a file
# and dd so that it leaves in one write.
raw() {
	local port=$1 b fmt=
	shift
	for b in "$@"; do fmt="$fmt\\x$b"; done
	printf "$fmt" >"$W/raw.bin"
	dd if="$W/raw.bin" bs=4096 2>/dev/null >"/dev/udp/127.0.0.1/$port"
}

RAW_ID=0
# raw_request <port> <tag> <User-Name hex bytes...>: an Access-Request without
# Message-Authenticator carrying NAS-Identifier = <tag> and the given User-Name octets.
raw_request() {
	local port=$1 tag=$2 t u len
	shift 2
	t=$(hex "$tag")
	u="$*"
	set -- $t
	local tlen=$#
	set -- $u
	local ulen=$#
	len=$((20 + 2 + tlen + 2 + ulen))
	RAW_ID=$(((RAW_ID + 1) % 256))
	raw "$port" 01 "$(printf '%02x' $RAW_ID)" 00 "$(printf '%02x' $len)" \
		$(hex "$(printf '%016d' "$RAW_ID")") \
		20 "$(printf '%02x' $((tlen + 2)))" $t \
		01 "$(printf '%02x' $((ulen + 2)))" $u
}

# seen <dir> <instance> <tag> <field>: field 3 = User-Name, 4 = User-Password, 5 = nul marker
seen() { awk -F'\t' -v h="$2" -v t="$3" -v f="$4" '$1 == h && $2 == t { print $f }' "$1/seen.tsv"; }

# check_value <scenario> <dir> <case> <instance> <tag> <field> <expected: value:<repr> | fail> <log slice>
check_value() {
	local s=$1 d=$2 c=$3 h=$4 tag=$5 f=$6 exp=$7 slice=$8 got actual ok=FAIL
	got=$(seen "$d" "$h" "$tag" "$f")
	if [ -n "$got" ]; then
		actual="value:$got"
		[ "$(seen "$d" "$h" "$tag" 5 | sort -u)" = - ] || actual="$actual (NUL in a value)"
	elif printf '%s\n' "$slice" | grep -q 'mod_populate_vps failed'; then
		actual=fail
	else
		actual="not called, no mod_populate_vps line"
	fi
	[ "$actual" = "$exp" ] && ok=PASS
	record "$s" "$c [$h]" "$exp" "$actual" "$ok"
}

# raw_case <scenario> <dir> <case> <User-Name hex> <expected: default> <replace> <ignore> <backslashreplace>
#   One raw request per instance, one after the other, so that each log slice is one instance's.
raw_case() {
	local s=$1 d=$2 c=$3 un=$4 tag n slice h
	shift 4
	tag=$(echo "$c" | tr -c 'A-Za-z0-9\n' '_')
	for h in $HANDLERS; do
		n=$(wc -l <"$d/radiusd.log")
		raw_request "$(port_of "$h")" "$tag" $un
		sleep 0.3
		slice=$(tail -n +"$((n + 1))" "$d/radiusd.log")
		printf '%s\n' "$slice" >"$d/probe-$tag-$h.log"
		check_value "$s" "$d" "$c" "$h" "$tag" 3 "$1" "$slice"
		shift
	done
}

MA_OFF='Message-Authenticator !* ANY'

# rc <port> <secret> <count> <attrs...>: <count> radclient runs of one request each (each with its
# own ID and Request Authenticator).  Not "-c <count>": radclient stops repeating after the first
# request without a valid reply, and radclient 3.2.10 crashes after a second reply it cannot
# verify, so with the wrong secret one run would send only one request.
rc() {
	local port=$1 secret=$2 count=$3 i
	shift 3
	for i in $(seq 1 "$count"); do
		printf '%s\n' "$@" | paste -sd, - |
			"$RADCLIENT" -D "$DICTDIR" -r 1 -t 1 -q "127.0.0.1:$port" auth "$secret" >/dev/null 2>&1
	done
}

scenario_check() {
	local s=check d=$W/check out h
	raddb "$d"
	out=$d/check.log
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$out" 2>&1; then
		record $s "radiusd -XC, every handler" "ok" "ok" PASS
	else
		record $s "radiusd -XC, every handler" "ok" "fails: $(grep -i error "$out" | head -1)" FAIL
	fi
	d=$W/check-strict
	raddb "$d" strict
	out=$d/check.log
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$out" 2>&1; then
		record $s "radiusd -XC, unicode_errors = strict" "ok" "ok" PASS
	else
		record $s "radiusd -XC, unicode_errors = strict" "ok" "fails: $(grep -i error "$out" | head -1)" FAIL
	fi
}

scenario_errors() {
	local s=errors v d out i
	# encode-only handlers, handlers that give lone surrogates, a typo, the wrong case, empty
	for v in bogus xmlcharrefreplace namereplace surrogateescape surrogatepass Replace ""; do
		d=$W/errors-${v:-empty}
		raddb "$d" "$v"
		out=$d/check.log
		if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$out" 2>&1; then
			record $s "unicode_errors = \"$v\"" "config error" "accepted" FAIL
		elif grep -q "Invalid 'unicode_errors' value \"$v\"" "$out"; then
			record $s "unicode_errors = \"$v\"" "config error" "config error" PASS
		else
			record $s "unicode_errors = \"$v\"" "config error" "fails without the message: $(grep -i error "$out" | head -1)" FAIL
		fi
	done
	# not only -C: the daemon refuses to start
	d=$W/errors-start
	raddb "$d" bogus
	"$RADIUSD" -fxx -d "$d" -D "$DICTDIR" -l "$d/radiusd.log" >"$d/stdout.log" 2>&1 &
	i=$!
	sleep 3
	if kill -0 "$i" 2>/dev/null; then
		kill "$i"; wait "$i" 2>/dev/null
		record $s "radiusd with unicode_errors = bogus" "does not start" "running" FAIL
	elif grep -q "Invalid 'unicode_errors' value \"bogus\"" "$d/radiusd.log" "$d/stdout.log"; then
		record $s "radiusd with unicode_errors = bogus" "does not start" "does not start" PASS
	else
		record $s "radiusd with unicode_errors = bogus" "does not start" "exited without the message" FAIL
	fi
}

scenario_main() {
	local s=main d=$W/main n slice h tag cnt fffd nul calls fails c ok
	raddb "$d"
	start "$d" || { record $s "radiusd starts" ok "no" FAIL; return; }

	# Raw Access-Requests (no Message-Authenticator), User-Name octets as given.
	# Expected per instance: default (no option), replace, ignore, backslashreplace.
	raw_case $s "$d" "ASCII bob" "62 6f 62" \
		"value:'bob'" "value:'bob'" "value:'bob'" "value:'bob'"
	raw_case $s "$d" "UTF-8 Cyrillic, 2-byte" "d0 bf d1 80 d0 b8" \
		"value:'\\u043f\\u0440\\u0438'" "value:'\\u043f\\u0440\\u0438'" "value:'\\u043f\\u0440\\u0438'" "value:'\\u043f\\u0440\\u0438'"
	raw_case $s "$d" "UTF-8 3-byte and 4-byte" "e2 82 ac f0 9f 98 80" \
		"value:'\\u20ac\\U0001f600'" "value:'\\u20ac\\U0001f600'" "value:'\\u20ac\\U0001f600'" "value:'\\u20ac\\U0001f600'"
	raw_case $s "$d" "\\377bob" "ff 62 6f 62" \
		fail "value:'\\ufffdbob'" "value:'bob'" "value:'\\\\xffbob'"
	raw_case $s "$d" "cp1251 name" "cf f0 e8" \
		fail "value:'\\ufffd\\ufffd\\ufffd'" "value:''" "value:'\\\\xcf\\\\xf0\\\\xe8'"
	raw_case $s "$d" "valid then invalid" "d0 bf ff" \
		fail "value:'\\u043f\\ufffd'" "value:'\\u043f'" "value:'\\u043f\\\\xff'"
	raw_case $s "$d" "truncated sequence at the end" "61 62 d0" \
		fail "value:'ab\\ufffd'" "value:'ab'" "value:'ab\\\\xd0'"
	raw_case $s "$d" "surrogate code point (ED A0 80)" "ed a0 80" \
		fail "value:'\\ufffd\\ufffd\\ufffd'" "value:''" "value:'\\\\xed\\\\xa0\\\\x80'"
	# the value still ends at the first NUL: nothing after it reaches Python
	raw_case $s "$d" "\\377 NUL bob" "ff 00 62 6f 62" \
		fail "value:'\\ufffd'" "value:''" "value:'\\\\xff'"
	raw_case $s "$d" "bob NUL (trailing)" "62 6f 62 00" \
		"value:'bob'" "value:'bob'" "value:'bob'" "value:'bob'"
	raw_case $s "$d" "bob NUL \\377" "62 6f 62 00 ff" \
		"value:'bob'" "value:'bob'" "value:'bob'" "value:'bob'"

	# debug line for a value that needed the handler, none for a valid one (N12)
	slice=$(cat "$d/probe-_377bob-replace.log")
	if printf '%s\n' "$slice" | grep -q 'User-Name is not valid UTF-8, decoding it with unicode_errors = replace'; then
		record $s "debug line for \\377bob [replace]" "line" "line" PASS
	else
		record $s "debug line for \\377bob [replace]" "line" "none" FAIL
	fi
	slice=$(cat "$d/probe-UTF_8_Cyrillic__2_byte-replace.log")
	if printf '%s\n' "$slice" | grep -q 'is not valid UTF-8'; then
		record $s "no debug line for valid UTF-8" "none" "line" FAIL
	else
		record $s "no debug line for valid UTF-8" "none" "none" PASS
	fi

	# radclient: PAP with the right secret, UTF-8 password, no Message-Authenticator
	for h in default replace; do
		n=$(wc -l <"$d/radiusd.log")
		rc "$(port_of "$h")" right 1 'User-Name = "alice"' 'User-Password = "\320\277\320\260\321\201"' \
			'NAS-Identifier = "pap_right"' "$MA_OFF"
		sleep 0.3
		check_value $s "$d" "PAP right secret, UTF-8 password" "$h" pap_right 4 "value:'\\u043f\\u0430\\u0441'" \
			"$(tail -n +"$((n + 1))" "$d/radiusd.log")"
	done

	# radclient: User-Name with \377, right secret, no Message-Authenticator, series of 20
	for h in default replace; do
		tag=rc_377_$h
		n=$(wc -l <"$d/radiusd.log")
		rc "$(port_of "$h")" right 20 'User-Name = "\377bob"' 'User-Password = "pw"' \
			"NAS-Identifier = \"$tag\"" "$MA_OFF"
		sleep 1
		calls=$(seen "$d" "$h" "$tag" 3 | wc -l)
		fails=$(tail -n +"$((n + 1))" "$d/radiusd.log" | grep -c 'mod_populate_vps failed')
		cnt=$(seen "$d" "$h" "$tag" 3 | grep -c "^'\\\\ufffdbob'\$")
		if [ "$h" = default ]; then
			c="0 calls, 20 fail"
			[ "$calls" = 0 ] && [ "$fails" = 20 ] && ok=PASS || ok=FAIL
		else
			c="20 calls, all '\\ufffdbob', 0 fail"
			[ "$calls" = 20 ] && [ "$cnt" = 20 ] && [ "$fails" = 0 ] && ok=PASS || ok=FAIL
		fi
		record $s "radclient \\377bob x20 [$h]" "batch:$c" "batch:$calls calls, $cnt '\\ufffdbob', $fails fail" "$ok"
	done

	# radclient: PAP with the WRONG secret and no Message-Authenticator, series of 20.  radiusd
	# decrypts User-Password with its own secret and gets 16 random-looking octets; about 1 in 100
	# is valid UTF-8 up to its first NUL by chance, so the rule allows a few.
	for h in default replace; do
		tag=wrong_$h
		n=$(wc -l <"$d/radiusd.log")
		rc "$(port_of "$h")" wrong 20 'User-Name = "bob"' 'User-Password = "secret12"' \
			"NAS-Identifier = \"$tag\"" "$MA_OFF"
		sleep 1
		calls=$(seen "$d" "$h" "$tag" 4 | wc -l)
		fails=$(tail -n +"$((n + 1))" "$d/radiusd.log" | grep -c 'mod_populate_vps failed')
		fffd=$(seen "$d" "$h" "$tag" 4 | grep -c 'ufffd')
		nul=$(seen "$d" "$h" "$tag" 5 | grep -c nul)
		if [ "$h" = default ]; then
			c=">=15 fail, calls + fail = 20"
			[ "$fails" -ge 15 ] && [ $((calls + fails)) = 20 ] && ok=PASS || ok=FAIL
		else
			c="20 calls, >=15 with U+FFFD, no NUL, 0 fail"
			[ "$calls" = 20 ] && [ "$fffd" -ge 15 ] && [ "$nul" = 0 ] && [ "$fails" = 0 ] && ok=PASS || ok=FAIL
		fi
		record $s "PAP wrong secret, no MA, x20 [$h]" "batch:$c" \
			"batch:$calls calls, $fffd with U+FFFD, $nul with NUL, $fails fail" "$ok"
	done

	# control: the same with Message-Authenticator is dropped before any module runs
	tag=wrong_ma
	n=$(wc -l <"$d/radiusd.log")
	rc "$(port_of replace)" wrong 1 'User-Name = "bob"' 'User-Password = "secret12"' "NAS-Identifier = \"$tag\""
	sleep 0.3
	calls=$(seen "$d" replace "$tag" 4 | wc -l)
	if [ "$calls" = 0 ] && tail -n +"$((n + 1))" "$d/radiusd.log" | grep -q 'invalid Message-Authenticator'; then
		record $s "PAP wrong secret, with MA [replace]" "dropped" "dropped" PASS
	else
		record $s "PAP wrong secret, with MA [replace]" "dropped" "$calls calls" FAIL
	fi
	stop
}

trap stop EXIT
say "radiusd: $("$RADIUSD" -v | head -1)"
for sc in $SCEN; do
	say "scenario $sc"
	"scenario_$sc"
done

{
	echo "# rlm_python3 unicode_errors harness"
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
