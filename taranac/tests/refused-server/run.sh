#!/bin/bash
# "refused_virtual_server" harness: radiusd with listeners which have the option and listeners
# which do not, probed on 127.0.0.1 and ::1 by radclient and by nas.py (a minimal client which
# counts every datagram that comes back, verified or not).
#
#   run.sh <workdir> [scenario ...]        default: all (dictionary check errors signature malformed)
#
# Needs in PATH (or RADIUSD=/path, RADCLIENT=/path): radiusd and radclient built from the ref
# under test, python3, bash, ip.  No extra addresses and no capabilities, but ::1 must exist:
#
#   docker run --rm --network none --sysctl net.ipv6.conf.all.disable_ipv6=0 <image> run.sh /tmp/w
#
# Output: <workdir>/results.tsv (scenario, case, expected, actual, verdict),
#         <workdir>/summary.md, a directory per scenario with raddb, radiusd.log, refused.log
#         (one line per run of the refused virtual server), normal.log (one line per request
#         the normal virtual server handled) and sink.log (datagrams sent to the proxy and CoA
#         sinks).
# Exit:   0 all PASS, 1 any FAIL.
set -u
W=${1:?usage: run.sh <workdir> [scenario ...]}
shift
mkdir -p "$W"
W=$(cd "$W" && pwd)
H=$(cd "$(dirname "$0")" && pwd)
RADIUSD=${RADIUSD:-radiusd}
RADCLIENT=${RADCLIENT:-radclient}
DICTDIR=${DICTDIR:-/usr/share/freeradius}
LIBDIR=${LIBDIR:-/usr/lib/freeradius}
SCEN=${*:-dictionary check errors signature malformed}

RESULTS=$W/results.tsv
printf 'scenario\tcase\texpected\tactual\tverdict\n' >"$RESULTS"
FAILS=0

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

record() {	# scenario case expected actual verdict
	printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RESULTS"
	[ "$5" = PASS ] || FAILS=$((FAILS + 1))
	printf '  %-4s %-10s %-56s %s\n' "$5" "$1" "$2" "${4:0:90}"
}

# expect <scenario> <case> <expected> <actual>
expect() { if [ "$3" = "$4" ]; then record "$1" "$2" "$3" "$4" PASS; else record "$1" "$2" "$3" "$4" FAIL; fi; }

# The refused server logs one line per run: the NAS-Identifier is the probe's tag.
#   1 tag | 2 Refused-Reason | 3 Packet-Type | 4 User-Name | 5 Module-Failure-Message
#   6 source address | 7 destination port | 8 every request attribute
REFUSED_FORMAT='%{NAS-Identifier}|%{Refused-Reason}|%{Packet-Type}|%{User-Name}|%{Module-Failure-Message}|%{Packet-Src-IP-Address}%{Packet-Src-IPv6-Address}|%{Packet-Dst-Port}|%{pairs:request:}'

# raddb <dir> [max_attributes] [refused_virtual_server lines: "with" (default) or a raw line]
raddb() {
	local d=$1 maxattr=${2:-0}
	mkdir -p "$d/run"
	: >"$d/refused.log"
	: >"$d/normal.log"
	: >"$d/sink.log"
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
proxy_requests = yes
security {
	allow_core_dumps = no
	require_message_authenticator = no
	limit_proxy_state = no
	status_server = yes
	max_attributes = $maxattr
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
client lo4 {
	ipaddr = 127.0.0.1
	secret = right
	require_message_authenticator = no
	limit_proxy_state = no
}
client lo6 {
	ipv6addr = ::1
	secret = right
	require_message_authenticator = no
	limit_proxy_state = no
}

# The sinks (sink.py) never answer: they only show whether radiusd sent anything.
home_server sink_auth {
	type = auth
	ipaddr = 127.0.0.1
	port = 1912
	secret = right
	response_window = 1
	status_check = none
}
home_server_pool sink_pool {
	type = fail-over
	home_server = sink_auth
}
realm sinkrealm {
	auth_pool = sink_pool
}
home_server sink_coa {
	type = coa
	ipaddr = 127.0.0.1
	port = 3799
	secret = right
	coa {
		irt = 2
		mrt = 16
		mrc = 1
		mrd = 30
	}
}

modules {
	expr {
	}
	linelog refused_log {
		filename = $d/refused.log
		format = "$REFUSED_FORMAT"
	}
	linelog normal_log {
		filename = $d/normal.log
		format = "%{NAS-Identifier}|%{Packet-Type}"
	}
}

# Probes whose tag starts with "coa" or "proxy" ask for a CoA request or for proxying, here
# and in the normal server (the controls: there, both happen).
policy {
	coa_and_proxy {
		if (&NAS-Identifier =~ /^coa/) {
			update coa {
				&User-Name := "%{User-Name}"
				&Packet-Dst-IP-Address := 127.0.0.1
				&Packet-Dst-Port := 3799
			}
		}
		if (&NAS-Identifier =~ /^proxy/) {
			update control {
				&Proxy-To-Realm := "sinkrealm"
			}
		}
	}
}

server refused {
	authorize {
		refused_log
		coa_and_proxy
		# would be an Access-Accept in a normal server: still no reply
		if (&NAS-Identifier =~ /^reply/) {
			update reply {
				&Reply-Message := "not sent"
			}
			update control {
				&Auth-Type := Accept
			}
		}
	}
}

server s_on {
	listen {
		type = auth
		ipaddr = 127.0.0.1
		port = 1812
		refused_virtual_server = refused
	}
	listen {
		type = acct
		ipaddr = 127.0.0.1
		port = 1813
		refused_virtual_server = refused
	}
$(if [ "${V6:-1}" = 1 ]; then cat <<V6
	listen {
		type = auth
		ipv6addr = ::1
		port = 1812
		refused_virtual_server = refused
	}
	listen {
		type = acct
		ipv6addr = ::1
		port = 1813
		refused_virtual_server = refused
	}
V6
fi)
	authorize {
		normal_log
		coa_and_proxy
		update control {
			&Auth-Type := Accept
		}
	}
	authenticate {
	}
	accounting {
		normal_log
	}
}

# Upstream behaviour: no refused_virtual_server.
server s_off {
	listen {
		type = auth
		ipaddr = 127.0.0.1
		port = 1822
	}
	listen {
		type = acct
		ipaddr = 127.0.0.1
		port = 1823
	}
	authorize {
		normal_log
		update control {
			&Auth-Type := Accept
		}
	}
	authenticate {
	}
	accounting {
		normal_log
	}
}
CONF
}

PID=
SINK=
start() {	# <dir>
	local d=$1 i
	: >"$d/radiusd.log"
	python3 "$H/sink.py" "$d/sink.log" 1912 3799 &
	SINK=$!
	"$RADIUSD" -fxx -d "$d" -D "$DICTDIR" -l "$d/radiusd.log" >"$d/stdout.log" 2>&1 &
	PID=$!
	for i in $(seq 1 100); do
		grep -q 'Ready to process requests' "$d/radiusd.log" "$d/stdout.log" 2>/dev/null && return 0
		kill -0 "$PID" 2>/dev/null || break
		sleep 0.1
	done
	echo "radiusd did not start:"; tail -20 "$d/radiusd.log" "$d/stdout.log"
	stop
	return 1
}

stop() {
	[ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
	[ -n "$SINK" ] && kill "$SINK" 2>/dev/null && wait "$SINK" 2>/dev/null
	PID=
	SINK=
}

nas() { python3 "$H/nas.py" "$@"; }

# rc <host> <port> <auth|acct> <secret> <attrs...>: one radclient run, one request; prints
# "reply" or "no reply".  radclient adds Message-Authenticator to an Access-Request itself.
rc() {
	local host=$1 port=$2 cmd=$3 secret=$4 out
	shift 4
	case $host in *:*) host="[$host]" ;; esac
	out=$(printf '%s\n' "$@" | paste -sd, - |
		"$RADCLIENT" -D "$DICTDIR" -r 1 -t 1 "$host:$port" "$cmd" "$secret" 2>&1)
	if printf '%s\n' "$out" | grep -q 'Received .* Id '; then echo reply; else echo "no reply"; fi
}

# lines <dir> <tag>: refused.log lines for the tag
lines() { awk -F'|' -v t="$2" '$1 == t' "$1/refused.log"; }
count() { lines "$1" "$2" | wc -l; }
field() { lines "$1" "$2" | head -1 | cut -d'|' -f"$3"; }
normal() { awk -F'|' -v t="$2" '$1 == t' "$1/normal.log" | wc -l; }

# Attributes which depend on the secret, by name and as an attribute that did not decrypt.
SECRET_ATTRS='User-Password|Tunnel-Password|MS-MPPE|Message-Authenticator|Attr-2 |Attr-69|Attr-26\.311\.16|Attr-80'

# check_refused <scenario> <dir> <case> <tag> <reason> <packet type> <user> <message regex> <source>
check_refused() {
	local s=$1 d=$2 c=$3 tag=$4 reason=$5 type=$6 user=$7 msg=$8 src=$9 got exp pairs
	exp="1 line|$reason|$type|$user|message|$src|no secret-dependent attributes"
	got="$(count "$d" "$tag") line|$(field "$d" "$tag" 2)|$(field "$d" "$tag" 3)|$(field "$d" "$tag" 4)"
	if field "$d" "$tag" 5 | grep -Eq "$msg"; then got="$got|message"; else got="$got|message: $(field "$d" "$tag" 5)"; fi
	got="$got|$(field "$d" "$tag" 6)"
	# the message itself names Message-Authenticator: look at the other attributes
	pairs=$(field "$d" "$tag" 8 | sed 's/Module-Failure-Message = "[^"]*"//')
	if printf '%s\n' "$pairs" | grep -Eq "$SECRET_ATTRS"; then
		got="$got|secret-dependent attributes: $pairs"
	else
		got="$got|no secret-dependent attributes"
	fi
	expect "$s" "$c" "$exp" "$got"
}

scenario_dictionary() {
	local s=dictionary out n
	# N4: the number of Refused-Reason belongs to no other attribute of vendor 0 in any
	# dictionary radiusd loads, and the values are those of refused_reason_t.
	out=$(awk '
		/^BEGIN-VENDOR/ { v = 1 } /^END-VENDOR/ { v = 0 }
		/^ATTRIBUTE/ && !v && $5 !~ /vendor=/ { print $3 "\t" $2 "\t" FILENAME }' "$DICTDIR"/dictionary* )
	n=$(printf '%s\n' "$out" | awk -F'\t' '$2 == "Refused-Reason" { print $1 }')
	expect $s "Refused-Reason is defined once" "1" "$(printf '%s\n' "$n" | grep -c .)"
	expect $s "Refused-Reason number is not shared" "Refused-Reason" \
		"$(printf '%s\n' "$out" | awk -F'\t' -v n="$n" '$1 == n { print $2 }' | sort -u | paste -sd, -)"
	expect $s "Refused-Reason values" "Key-Mismatch=1,Malformed-Request=2,Wrong-Port=3,Message-Authenticator-Missing=4" \
		"$(awk '$1 == "VALUE" && $2 == "Refused-Reason" { print $3 "=" $4 }' "$DICTDIR"/dictionary* | paste -sd, -)"
}

scenario_check() {
	local s=check d=$W/check
	V6=0 raddb "$d"
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$d/check.log" 2>&1; then
		expect $s "radiusd -XC, option on auth and acct" ok ok
	else
		expect $s "radiusd -XC, option on auth and acct" ok "fails: $(grep -i error "$d/check.log" | head -1)"
	fi
}

# errors_case <case> <message regex> <text> <replacement>: the first <text> in radiusd.conf
# becomes <replacement>
errors_case() {
	local s=errors c=$1 msg=$2 d
	d=$W/errors-$(echo "$c" | tr -c 'A-Za-z0-9\n' '_')
	V6=0 raddb "$d"
	python3 -c 'import sys; f, o, n = sys.argv[1:]; t = open(f).read(); assert o in t; open(f, "w").write(t.replace(o, n, 1))' \
		"$d/radiusd.conf" "$3" "$4" || { expect $s "$c" "config error" "harness: no \"$3\""; return; }
	if "$RADIUSD" -XC -d "$d" -D "$DICTDIR" >"$d/check.log" 2>&1; then
		expect $s "$c" "config error" accepted
	elif grep -Eq "$msg" "$d/check.log"; then
		expect $s "$c" "config error" "config error"
	else
		expect $s "$c" "config error" "fails without the message: $(grep -i error "$d/check.log" | head -1)"
	fi
}

scenario_errors() {
	errors_case "no such server" 'No such server "nowhere" for "refused_virtual_server"' \
		'refused_virtual_server = refused' 'refused_virtual_server = nowhere'
	# the first listener of s_on becomes another type or protocol
	local l1=$'\t\ttype = auth\n\t\tipaddr = 127.0.0.1\n\t\tport = 1812\n'
	errors_case "on a status listener" '"refused_virtual_server" is allowed only in a UDP listen section' \
		"$l1" "${l1/auth/status}"
	errors_case "on a TCP auth listener" '"refused_virtual_server" is allowed only in a UDP listen section' \
		"$l1" "$l1"$'\t\tproto = tcp\n'
}

scenario_signature() {
	local s=signature d=$W/signature fam host port6 tag n out v6=1
	if ! ip -6 addr show dev lo 2>/dev/null | grep -q '::1/128'; then
		v6=0
		record $s "IPv6 ::1 on lo" "present" "absent (--sysctl net.ipv6.conf.all.disable_ipv6=0)" FAIL
	fi
	V6=$v6 raddb "$d"
	start "$d" || { record $s "radiusd starts" ok no FAIL; return; }

	for fam in v4 v6; do
		if [ "$fam" = v4 ]; then host=127.0.0.1; else host=::1; [ "$v6" = 1 ] || continue; fi

		# wrong secret, radclient: Access-Request (with the Message-Authenticator radclient adds)
		tag=rc_auth_$fam
		n=$(wc -l <"$d/radiusd.log")
		out=$(rc "$host" 1812 auth wrong 'User-Name = "bob"' 'User-Password = "secret12"' "NAS-Identifier = \"$tag\"")
		sleep 0.3
		expect $s "radclient Access-Request, wrong secret [$fam]: reply" "no reply" "$out"
		check_refused $s "$d" "radclient Access-Request, wrong secret [$fam]" "$tag" Key-Mismatch Access-Request bob \
			'invalid Message-Authenticator' "$host"
		if tail -n +"$((n + 1))" "$d/radiusd.log" |
			grep -q 'Dropping packet without response because of error: Received packet from .* with invalid Message-Authenticator'; then
			expect $s "radclient Access-Request, wrong secret [$fam]: log line" "unchanged" "unchanged"
		else
			expect $s "radclient Access-Request, wrong secret [$fam]: log line" "unchanged" "missing"
		fi

		# wrong secret, radclient: Accounting-Request
		tag=rc_acct_$fam
		out=$(rc "$host" 1813 acct wrong 'User-Name = "bob"' 'Acct-Status-Type = Start' 'Acct-Session-Id = "s1"' \
			"NAS-Identifier = \"$tag\"")
		sleep 0.3
		expect $s "radclient Accounting-Request, wrong secret [$fam]: reply" "no reply" "$out"
		check_refused $s "$d" "radclient Accounting-Request, wrong secret [$fam]" "$tag" Key-Mismatch Accounting-Request bob \
			'invalid Request Authenticator' "$host"

		# wrong secret, every kind of secret-dependent attribute; CHAP-Password is not one
		tag=all_auth_$fam
		out=$(nas "$host" 1812 wrong --user carol --password secret12 --chap --tunnel-password --mppe --nas-id "$tag")
		sleep 0.3
		expect $s "Access-Request with PAP, CHAP, Tunnel-Password, MPPE [$fam]: reply" "replies=0" "$out"
		check_refused $s "$d" "Access-Request with PAP, CHAP, Tunnel-Password, MPPE [$fam]" "$tag" Key-Mismatch \
			Access-Request carol 'invalid Message-Authenticator' "$host"
		if field "$d" "$tag" 8 | grep -q 'CHAP-Password'; then
			expect $s "CHAP-Password is kept [$fam]" kept kept
		else
			expect $s "CHAP-Password is kept [$fam]" kept "missing: $(field "$d" "$tag" 8)"
		fi

		tag=all_acct_$fam
		out=$(nas "$host" 1813 wrong --code acct --user carol --tunnel-password --nas-id "$tag")
		sleep 0.3
		expect $s "Accounting-Request with Tunnel-Password [$fam]: reply" "replies=0" "$out"
		check_refused $s "$d" "Accounting-Request with Tunnel-Password [$fam]" "$tag" Key-Mismatch \
			Accounting-Request carol 'invalid Request Authenticator' "$host"

		# a NAS retransmits: the same octets three times; each is a new request, none answered
		tag=retx_$fam
		out=$(nas "$host" 1812 wrong --user dave --password secret12 --nas-id "$tag" --send 3 --gap 1.2)
		sleep 0.3
		expect $s "Access-Request sent 3 times, wrong secret [$fam]" "replies=0, 3 lines" "$out, $(count "$d" "$tag") lines"
		tag=retx_acct_$fam
		out=$(nas "$host" 1813 wrong --code acct --user dave --nas-id "$tag" --send 3 --gap 1.2)
		sleep 0.3
		expect $s "Accounting-Request sent 3 times, wrong secret [$fam]" "replies=0, 3 lines" "$out, $(count "$d" "$tag") lines"

		# Status-Server: answered with the right secret, refused with the wrong one
		tag=status_wrong_$fam
		out=$(nas "$host" 1812 wrong --code status --nas-id "$tag")
		sleep 0.3
		expect $s "Status-Server, wrong secret [$fam]" "replies=0, 1 line Key-Mismatch|Status-Server" \
			"$out, $(count "$d" "$tag") line $(field "$d" "$tag" 2)|$(field "$d" "$tag" 3)"
		tag=status_right_$fam
		out=$(nas "$host" 1812 right --code status --nas-id "$tag")
		expect $s "Status-Server, right secret [$fam]" "replies=1 code=2, 0 lines" "$out, $(count "$d" "$tag") lines"

		# right secret: handled as before, the refused server does not run
		tag=right_auth_$fam
		out=$(rc "$host" 1812 auth right 'User-Name = "bob"' 'User-Password = "secret12"' "NAS-Identifier = \"$tag\"")
		sleep 0.3
		expect $s "radclient Access-Request, right secret [$fam]" "reply, handled 1, 0 lines" \
			"$out, handled $(normal "$d" "$tag"), $(count "$d" "$tag") lines"
		tag=right_acct_$fam
		out=$(rc "$host" 1813 acct right 'User-Name = "bob"' 'Acct-Status-Type = Start' 'Acct-Session-Id = "s1"' \
			"NAS-Identifier = \"$tag\"")
		sleep 0.3
		expect $s "radclient Accounting-Request, right secret [$fam]" "reply, handled 1, 0 lines" \
			"$out, handled $(normal "$d" "$tag"), $(count "$d" "$tag") lines"
	done

	# What the refused server asks for is not done.  The controls show that the same policy in
	# the normal server does send a CoA request and does proxy.
	# Proxying first: radiusd 3.2.10 (with or without this change) crashes when it proxies while a
	# CoA request it originated is still unanswered.
	tag=proxy_control
	out=$(nas 127.0.0.1 1812 right --user erin --nas-id "$tag" --wait 2)
	expect $s "control: normal server, Proxy-To-Realm" "Access-Request proxied" \
		"$(grep -q '^1912 1$' "$d/sink.log" && echo "Access-Request proxied" || echo "nothing sent")"
	: >"$d/sink.log"
	tag=proxy_refused
	out=$(nas 127.0.0.1 1812 wrong --user erin --nas-id "$tag" --wait 3)
	expect $s "refused server, Proxy-To-Realm" "replies=0, 1 line, nothing sent" \
		"$out, $(count "$d" "$tag") line, $([ -s "$d/sink.log" ] && echo "sent: $(paste -sd, "$d/sink.log")" || echo "nothing sent")"

	sleep 2
	tag=coa_control
	out=$(nas 127.0.0.1 1812 right --user erin --nas-id "$tag" --wait 2)
	sleep 1
	expect $s "control: normal server, update coa" "CoA-Request sent" \
		"$(grep -q '^3799 43$' "$d/sink.log" && echo "CoA-Request sent" || echo "nothing sent")"
	: >"$d/sink.log"
	tag=coa_refused
	out=$(nas 127.0.0.1 1812 wrong --user erin --nas-id "$tag" --wait 3)
	expect $s "refused server, update coa" "replies=0, 1 line, nothing sent" \
		"$out, $(count "$d" "$tag") line, $([ -s "$d/sink.log" ] && echo "sent: $(paste -sd, "$d/sink.log")" || echo "nothing sent")"

	tag=reply_refused
	out=$(nas 127.0.0.1 1812 wrong --user erin --nas-id "$tag")
	expect $s "refused server sets Auth-Type Accept and a reply" "replies=0, 1 line" "$out, $(count "$d" "$tag") line"

	# no option: upstream behaviour, dropped with the log line, nothing runs
	tag=off_auth
	n=$(wc -l <"$d/radiusd.log")
	out=$(nas 127.0.0.1 1822 wrong --user bob --password secret12 --nas-id "$tag")
	sleep 0.3
	expect $s "no option: Access-Request, wrong secret" "replies=0, 0 lines, handled 0" \
		"$out, $(count "$d" "$tag") lines, handled $(normal "$d" "$tag")"
	if tail -n +"$((n + 1))" "$d/radiusd.log" |
		grep -q 'Dropping packet without response because of error: Received packet from 127.0.0.1 with invalid Message-Authenticator'; then
		expect $s "no option: Access-Request, wrong secret: log line" present present
	else
		expect $s "no option: Access-Request, wrong secret: log line" present missing
	fi
	tag=off_acct
	n=$(wc -l <"$d/radiusd.log")
	out=$(nas 127.0.0.1 1823 wrong --code acct --user bob --nas-id "$tag")
	sleep 0.3
	expect $s "no option: Accounting-Request, wrong secret" "replies=0, 0 lines, handled 0" \
		"$out, $(count "$d" "$tag") lines, handled $(normal "$d" "$tag")"
	if tail -n +"$((n + 1))" "$d/radiusd.log" |
		grep -q 'Dropping packet without response because of error: Received Accounting-Request packet from client 127.0.0.1 with invalid Request Authenticator'; then
		expect $s "no option: Accounting-Request, wrong secret: log line" present present
	else
		expect $s "no option: Accounting-Request, wrong secret: log line" present missing
	fi
	tag=off_right
	out=$(nas 127.0.0.1 1822 right --user bob --password secret12 --nas-id "$tag")
	expect $s "no option: Access-Request, right secret" "replies=1 code=2" "$out"

	expect $s "radiusd still running" running "$(kill -0 "$PID" 2>/dev/null && echo running || echo exited)"
	stop
}

scenario_malformed() {
	local s=malformed d=$W/malformed n out
	# max_attributes = 4: rad_packet_ok() counts a Vendor-Specific as one attribute, rad_decode()
	# counts what is inside it, so a packet with 3 Cisco-AVPairs in one Vendor-Specific passes
	# the first check and the signature check, and fails to decode.
	V6=0 raddb "$d" 4
	start "$d" || { record $s "radiusd starts" ok no FAIL; return; }

	n=$(grep -c 'Malformed-Request' "$d/refused.log")
	out=$(nas 127.0.0.1 1813 right --code acct --nas-id m_acct --vsa-count 3)
	sleep 0.3
	expect $s "Accounting-Request, right secret, too many attributes" "replies=0, 1 line" \
		"$out, $(($(grep -c 'Malformed-Request' "$d/refused.log") - n)) line"
	out=$(tail -1 "$d/refused.log")
	expect $s "  the line" "|Malformed-Request|Accounting-Request||message|127.0.0.1|1813|Refused-Reason, Module-Failure-Message" \
		"$(printf '%s\n' "$out" | awk -F'|' '{ m = ($5 ~ /Too many attributes/) ? "message" : "message: " $5;
			print $1 "|" $2 "|" $3 "|" $4 "|" m "|" $6 "|" $7 "|" }')$(printf '%s\n' "$out" | cut -d'|' -f8 |
			grep -oE '(^|, )[A-Z][A-Za-z0-9-]+ = ' | sed 's/^, //; s/ = $//' | paste -sd, - | sed 's/,/, /g')"

	n=$(grep -c 'Malformed-Request' "$d/refused.log")
	out=$(nas 127.0.0.1 1812 right --code auth --nas-id m_auth --vsa-count 3)
	sleep 0.3
	expect $s "Access-Request with a valid Message-Authenticator, too many attributes" "replies=0, 1 line" \
		"$out, $(($(grep -c 'Malformed-Request' "$d/refused.log") - n)) line"

	out=$(nas 127.0.0.1 1813 right --code acct --nas-id m_ok --vsa-count 1)
	expect $s "control: Accounting-Request within max_attributes" "replies=1 code=5, handled 1" \
		"$out, handled $(normal "$d" m_ok)"

	n=$(wc -l <"$d/refused.log")
	out=$(nas 127.0.0.1 1823 right --code acct --nas-id m_off --vsa-count 3)
	sleep 0.3
	expect $s "no option: too many attributes" "replies=0, 0 lines" "$out, $(($(wc -l <"$d/refused.log") - n)) lines"
	stop
}

trap stop EXIT
say "radiusd: $("$RADIUSD" -v | head -1)"
for sc in $SCEN; do
	say "scenario $sc"
	"scenario_$sc"
done

{
	echo "# refused_virtual_server harness"
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
