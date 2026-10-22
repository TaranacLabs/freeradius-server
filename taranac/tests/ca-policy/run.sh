#!/bin/bash
# ca_policy harness: runs radiusd (EAP-TLS, check_crl) against eapol_test on 127.0.0.1.
#
#   run.sh <workdir> [scenario ...]        default: all; "fast" = all but the SLOW 15 and 16;
#                                          "vg" = 4 5 8 9 with radiusd under valgrind (memcheck)
#
# Needs in PATH (or RADIUSD=/path): radiusd built from the ref under test, eapol_test,
# openssl >= 3.0, python3.  Every scenario starts its own radiusd on its own port, so a
# daemon is always fresh.  SLOW scenarios 15/16 wait for
# ca_path_reload_interval (300 s) and run in the background next to the others.
#
# Output: <workdir>/results.tsv (scenario, case, expected, actual, verdict), times.tsv,
#         <workdir>/summary.md, <workdir>/spki-fixtures/, a directory per scenario with
#         raddb, radiusd.log and per-probe logs.
# Exit:   0 all PASS (RECORD rows are measurements), 1 any FAIL, 2 any INCONCLUSIVE.
#
# Verdicts:
#   Reject N  - eapol_test fails AND the probe's slice of the server log has
#               "OpenSSL says error N".
#   Accept, chain without a configured CA - eapol_test succeeds AND since this daemon
#               started the log has "CRL not checked ... issuer key sha256:<issuer SPKI>".
#   Accept    - eapol_test succeeds.
#   marker    - every scenario checks "tls: ca_policy: N entries", N = number of lines.
#   reload    - a scenario that relies on the store being rebuilt needs
#               "Flushing X509 store" in the log, else INCONCLUSIVE.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: run.sh <workdir> [scenario ...]}
shift
mkdir -p "$W"
W=$(cd "$W" && pwd)
RADIUSD=${RADIUSD:-radiusd}
DICTDIR=${DICTDIR:-/usr/share/freeradius}
LIBDIR=${LIBDIR:-/usr/lib/freeradius}
ALL="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 17 18 19 20 21 22 23 24 15 16"
VALGRIND=${VALGRIND:-0}
case "${*:-all}" in
all)  SCEN=$ALL ;;
fast) SCEN="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 17 18 19 20 21 22 23 24" ;;
vg)   SCEN="4 5 8 9"; VALGRIND=1 ;;
*)    SCEN=$* ;;
esac
# eapol_test timeouts: a daemon under valgrind is many times slower
ET_T=15; ET_TO=40; START_WAIT=100
[ "$VALGRIND" = 1 ] && { ET_T=90; ET_TO=150; START_WAIT=900; }
# the marker of the EAP tls-config (a binary without ca_policy prints none)
MARK_RE='tls: ca_policy: [0-9]+ entries in tls-config tls-nac'

now() { date +%s; }
LOG=$W/run.log
: >"$LOG"
say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

# ---- PKI and reference SPKI hashes -----------------------------------------------------------
P=$W/pki
if [ ! -f "$P/leaf/server.pem" ]; then
	rm -rf "$P"
	sh "$HERE/pki.sh" "$P" | tee -a "$LOG" || exit 1
fi

# Reference SPKI: openssl asn1parse.  The SPKI is the 7th child of the TBSCertificate (d=2),
# the 6th if there is no [0] version.  Then the raw bytes are cut out with -offset/-length.
ref_spki() {
	local pem=$1 line o hl l
	line=$(openssl asn1parse -in "$pem" -i | awk '
		{ if (!match($0, /d=[0-9]+/)) next; d = substr($0, RSTART + 2, RLENGTH - 2) + 0 }
		d == 1 { t++; next }
		t == 1 && d == 2 { n++; L[n] = $0 }
		END { k = (L[1] ~ /cont \[ 0 \]/) ? 1 : 0; print L[k + 6] }')
	o=${line%%:*}; o=${o// /}
	hl=$(sed -n 's/.*hl=\([0-9]*\).*/\1/p' <<<"$line")
	l=$(sed -n 's/.* l= *\([0-9]*\).*/\1/p' <<<"$line")
	openssl asn1parse -in "$pem" -offset "$o" -length $((hl + l)) -noout -out "$W/.spki.der" >/dev/null || return 1
	sha256sum "$W/.spki.der" | cut -d' ' -f1
}
py_spki() { python3 -I "$HERE/spki.py" hash "$1"; }

cert() { # cert <name> -> path of a CA certificate
	case $1 in
	Rre) echo "$P/Rre/cert.pem" ;;
	Sx)  echo "$P/Sx/cert.pem" ;;
	Nn)  echo "$P/N-nonull/cert.pem" ;;
	Lu)  echo "$P/leaf/u-ok.pem" ;;		# a client certificate, trusted directly
	*)   echo "$P/$1/cert.pem" ;;
	esac
}
declare -A H
for c in R Rre S Sx U R2 P I E PSS N Nn SRV A B Qold Qnew Sq Lu; do H[$c]=$(ref_spki "$(cert $c)") || { say "cannot hash $c"; exit 1; }; done

# ---- result rows ------------------------------------------------------------------------------
row() { # row <case> <expected> <actual> <PASS|FAIL|RECORD|INCONCLUSIVE>
	printf '%s\t%s\t%s\t%s\t%s\n' "$SC" "$1" "$2" "$3" "$4" >>"$W/res-$SC.tsv"
	say "  [$4] $SC/$1: expected: $2 | got: $3"
}

# ---- configuration ----------------------------------------------------------------------------
# Per scenario: CA="R S U", CRLS="S", POLICY="<hash> ..." (each becomes '<hash> crl'),
# RAW_POLICY=(lines verbatim), CHECK_CRL=yes|no, RELOAD=""|300, EXTRA_TLS, PEAP=0|1
reset_conf() { CA=""; CRLS=""; POLICY=""; RAW_POLICY=(); CHECK_CRL=yes; RELOAD=""; EXTRA_TLS=""; PEAP=0; }

gen_conf() { # gen_conf <dir> <port>
	local d=$1 port=$2 c h l
	rm -rf "$d"
	mkdir -p "$d/raddb/mods-enabled" "$d/raddb/sites-enabled" "$d/crl"
	: >"$d/ca.pem"
	for c in $CA; do cat "$(cert "$c")" >>"$d/ca.pem"; done
	for c in $CRLS; do cp "$P/crl/$c.pem" "$d/crl/$c.pem"; done
	openssl rehash "$d/crl" >/dev/null 2>&1
	NLINES=0
	local pol=""
	for h in $POLICY; do pol+="		ca_policy = \"$h crl\""$'\n'; NLINES=$((NLINES + 1)); done
	for l in "${RAW_POLICY[@]}"; do pol+="		ca_policy = \"$l\""$'\n'; NLINES=$((NLINES + 1)); done

	cat >"$d/raddb/radiusd.conf" <<C
prefix = /usr
exec_prefix = /usr
sysconfdir = /etc
localstatedir = /var
sbindir = /usr/sbin
logdir = $d
raddbdir = $d/raddb
radacctdir = $d
name = radiusd
confdir = \${raddbdir}
modconfdir = \${confdir}/mods-config
certdir = \${confdir}/certs
cadir = \${confdir}/certs
run_dir = $d
db_dir = $d
libdir = $LIBDIR
dictdir = $DICTDIR
pidfile = $d/radiusd.pid
max_request_time = 30
cleanup_delay = 5
max_requests = 1024
hostname_lookups = no
log {
	destination = stdout
	auth = yes
}
security {
	allow_vulnerable_openssl = yes
}
thread pool {
	start_servers = 2
	max_servers = 4
	min_spare_servers = 1
	max_spare_servers = 4
}
client local {
	ipaddr = 127.0.0.1
	secret = testing123
}
modules {
\$INCLUDE \${confdir}/mods-enabled/
}
policy {
}
\$INCLUDE \${confdir}/sites-enabled/
C
	local crl_line="" rl_line="" peap=""
	[ "$CHECK_CRL" = yes ] && crl_line="check_crl = yes"
	[ -n "$RELOAD" ] && rl_line="ca_path_reload_interval = $RELOAD"
	if [ "$PEAP" = 1 ]; then
		peap="	peap {
		tls = tls-nac
		default_eap_type = mschapv2
		virtual_server = \"inner-tunnel\"
	}
	mschapv2 {
	}"
		cat >"$d/raddb/mods-enabled/mschap" <<'C'
mschap {
}
C
		cat >"$d/raddb/sites-enabled/inner-tunnel" <<'C'
server inner-tunnel {
	authorize {
		update control {
			&Cleartext-Password := "capol-pass"
		}
		eap {
			ok = return
		}
	}
	authenticate {
		Auth-Type eap {
			eap
		}
		Auth-Type MS-CHAP {
			mschap
		}
	}
}
C
	fi
	cat >"$d/raddb/mods-enabled/eap" <<C
eap {
	default_eap_type = tls
	timer_expire = 60
	ignore_unknown_eap_types = no
	max_sessions = 4096
	tls-config tls-nac {
		private_key_file = $P/leaf/server.key
		certificate_file = $P/leaf/server_chain.pem
		ca_file = $d/ca.pem
		ca_path = $d/crl
		$crl_line
		$rl_line
$pol		cipher_list = "DEFAULT"
		tls_min_version = "1.2"
		tls_max_version = "1.2"
		cache {
			enable = no
		}
$EXTRA_TLS
	}
	tls {
		tls = tls-nac
	}
$peap
}
C
	cat >"$d/raddb/sites-enabled/default" <<C
server default {
	listen {
		type = auth
		ipaddr = 127.0.0.1
		port = $port
	}
	authorize {
		eap {
			ok = return
		}
	}
	authenticate {
		Auth-Type eap {
			eap
		}
	}
	post-auth {
		update reply {
			&Reply-Message := "capol issuer=<%{TLS-Client-Cert-Issuer}> serial=<%{TLS-Client-Cert-Serial}>"
		}
	}
}
C
}

# ---- daemon -----------------------------------------------------------------------------------
port_of() { # one port block per scenario, so that background SLOW scenarios never collide
	local n=${1//[!0-9]/} s=${1//[0-9]/} o=0
	[ -n "$s" ] && o=$(( $(printf '%d' "'$s") - 96 ))
	echo $((18000 + n * 20 + o))
}

srv_start() { # srv_start <name>: D, PORT, SLOG; 0 = up
	D=$W/sc-$1; PORT=$(port_of "$1"); SLOG=$D/radiusd.log
	gen_conf "$D" "$PORT"
	if [ "$VALGRIND" = 1 ]; then
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=definite --errors-for-leak-kinds=definite \
			--num-callers=30 --log-file="$D/valgrind.log" \
			"$(command -v "$RADIUSD")" -fxx -l stdout -d "$D/raddb" >"$SLOG" 2>&1 &
	else
		"$RADIUSD" -fxx -l stdout -d "$D/raddb" >"$SLOG" 2>&1 &
	fi
	SPID=$!
	T0=$(now)
	local i
	for i in $(seq 1 "$START_WAIT"); do
		grep -q 'Ready to process requests' "$SLOG" && return 0
		kill -0 "$SPID" 2>/dev/null || break
		sleep 0.2
	done
	row "start" "radiusd running" "did not start: $(grep -E 'rror|ca_policy' "$SLOG" | tail -3 | tr '\n' ' ')" FAIL
	return 1
}
srv_stop() {
	kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null
	[ "$VALGRIND" = 1 ] && vg_check
}

# valgrind: count the error and definite-leak records whose stack has our code in it
vg_check() {
	local f=$D/valgrind.log total ours
	if [ ! -s "$f" ] || ! grep -q 'ERROR SUMMARY' "$f"; then row valgrind "memcheck report" "no ERROR SUMMARY in valgrind.log" FAIL; return; fi
	total=$(sed -n 's/.*ERROR SUMMARY: \([0-9,]*\) errors.*/\1/p' "$f" | tail -1)
	ours=$(gawk 'BEGIN { RS = "\n==[0-9]+== \n" } /tls_ca_policy|ca_policy_|cbtls_verify/ { n++ } END { print n + 0 }' "$f")
	if [ "$ours" = 0 ]; then row valgrind "no memcheck record in ca_policy / cbtls_verify" "records in our code: 0 (ERROR SUMMARY: $total)" PASS
	else row valgrind "no memcheck record in ca_policy / cbtls_verify" "records in our code: $ours (ERROR SUMMARY: $total)" FAIL; fi
}

# eapol_conf <label> <leaf> [extra CA cert name ...]: writes $D/<label>.eapol.conf
eapol_conf() {
	local label=$1 leaf=$2 c
	shift 2
	cat "$P/leaf/$leaf.pem" >"$D/$label.chain.pem"
	for c in "$@"; do cat "$(cert "$c")" >>"$D/$label.chain.pem"; done
	if [ "$leaf" = peap ]; then
		cat >"$D/$label.eapol.conf" <<C
network={
	key_mgmt=IEEE8021X
	eap=PEAP
	identity="peap-user"
	password="capol-pass"
	phase2="auth=MSCHAPV2"
	ca_cert="$P/SRV/cert.pem"
	eapol_flags=0
}
C
	else
		cat >"$D/$label.eapol.conf" <<C
network={
	key_mgmt=IEEE8021X
	eap=TLS
	identity="$leaf"
	ca_cert="$P/SRV/cert.pem"
	client_cert="$D/$label.chain.pem"
	private_key="$P/leaf/$leaf.key"
	eapol_flags=0
}
C
	fi
}

# probe <label> <leaf> [extra CA cert name ...]: V = ACCEPT|REJECT, E = ",3,23,", PLOG = server log slice
probe() {
	local label=$1 n0
	eapol_conf "$@"
	n0=$(wc -l <"$SLOG")
	if timeout "$ET_TO" eapol_test -c "$D/$label.eapol.conf" -a 127.0.0.1 -p "$PORT" -s testing123 -t "$ET_T" \
		>"$D/$label.eapol.log" 2>&1 && grep -q '^SUCCESS' "$D/$label.eapol.log"; then
		V=ACCEPT
	else
		V=REJECT
	fi
	sleep 0.3
	PLOG=$D/$label.srv.log
	tail -n +$((n0 + 1)) "$SLOG" >"$PLOG"
	E=,$(grep -o 'OpenSSL says error [0-9]*' "$PLOG" | awk '{print $4}' | sort -un | tr '\n' ',')
}

got() { echo "$V err=${E#,}"; }

expect_reject() { # expect_reject <case> <code> [regr]
	# "regr": the same verdict on a binary without ca_policy -- a regression check, not evidence for the patch
	local x="Reject $2"
	[ "${3:-}" = regr ] && x="Reject $2 [regression]"
	if [ "$V" = REJECT ] && [[ $E == *,$2,* ]]; then row "$1" "$x" "$(got)" PASS
	else row "$1" "$x" "$(got)" FAIL; fi
}
expect_reject_any() { # expect_reject_any <case> "<code> <code>..."
	local c
	for c in $2; do [ "$V" = REJECT ] && [[ $E == *,$c,* ]] && { row "$1" "Reject ${2// / or }" "$(got)" PASS; return; }; done
	row "$1" "Reject ${2// / or }" "$(got)" FAIL
}
expect_accept() { # expect_accept <case>
	if [ "$V" = ACCEPT ]; then row "$1" "Accept" "$(got)" PASS; else row "$1" "Accept" "$(got)" FAIL; fi
}
warns_for() { grep -c "CRL not checked for .*issuer key sha256:$1)" "$SLOG"; }
warns_direct() { grep -c "CRL not checked for .*trusted directly, its own key sha256:$1)" "$SLOG"; }
expect_accept_unconf() { # expect_accept_unconf <case> <issuer CA name>
	local w; w=$(warns_for "${H[$2]}")
	if [ "$V" = ACCEPT ] && [ "$w" -ge 1 ]; then row "$1" "Accept + WARN for $2" "$(got) warn=$w" PASS
	else row "$1" "Accept + WARN for $2" "$(got) warn=$w" FAIL; fi
}
marker_in() { grep -oE "$MARK_RE" "$1" | sort -u | tr '\n' ';'; }
expect_marker() { # expect_marker <N>
	local m x="tls: ca_policy: $1 entries in tls-config tls-nac"
	m=$(marker_in "$SLOG")
	if [ "$m" = "$x;" ]; then row marker "$x" "$m" PASS; else row marker "$x" "${m:-none}" FAIL; fi
}

xc() { # xc <name>: run radiusd -XC on a generated config, XC_RC, XC_LOG
	D=$W/sc-$1; gen_conf "$D" "$(port_of "$1")"; XC_LOG=$D/xc.log
	"$RADIUSD" -XC -d "$D/raddb" >"$XC_LOG" 2>&1
	XC_RC=$?
}

# ---- scenarios --------------------------------------------------------------------------------
sc0() { # -XC with valid lines exits 0 and prints the marker (an old binary: exit 0, no marker)
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]} ${H[U]}"
	xc 0
	local m; m=$(marker_in "$XC_LOG")
	if [ "$XC_RC" = 0 ] && [ "$m" = "tls: ca_policy: 2 entries in tls-config tls-nac;" ]; then row xc-valid "exit 0 + marker 2" "exit $XC_RC, ${m:-no marker}" PASS
	else row xc-valid "exit 0 + marker 2" "exit $XC_RC, ${m:-no marker}" FAIL; fi
	reset_conf; CA="R S U"; CRLS="S"
	xc 0n
	m=$(marker_in "$XC_LOG")
	if [ "$XC_RC" = 0 ] && [ "$m" = "tls: ca_policy: 0 entries in tls-config tls-nac;" ]; then row xc-none "exit 0 + marker 0" "exit $XC_RC, ${m:-no marker}" PASS
	else row xc-none "exit 0 + marker 0" "exit $XC_RC, ${m:-no marker}" FAIL; fi
}

sc1() { # no ca_policy: upstream behaviour
	reset_conf; CA="R S U"; CRLS="S"
	srv_start 1 || return
	expect_marker 0
	probe u-ok u-ok; expect_reject u-ok 3
	probe s-rev s-rev; expect_reject s-rev 23 regr
	probe s-ok s-ok; expect_accept s-ok
	srv_stop
}

sc2() { # policy {S}: S chains checked, U chains not, one WARN for two U clients
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	srv_start 2 || return
	expect_marker 1
	probe s-ok s-ok; expect_accept s-ok
	probe s-rev s-rev; expect_reject s-rev 23 regr
	probe u-ok-1 u-ok; expect_accept_unconf u-ok-1 U
	probe u-ok-2 u-ok; expect_accept_unconf u-ok-2 U
	local w; w=$(warns_for "${H[U]}")
	if [ "$w" = 1 ]; then row warn-once "1 WARN for U after 2 clients" "$w" PASS; else row warn-once "1 WARN for U after 2 clients" "$w" FAIL; fi
	srv_stop
}

sc3() { # unconfigured chain: only CRL errors are cleared
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	srv_start 3 || return
	expect_marker 1
	probe u-expired u-expired; expect_reject u-expired 10
	probe u-forged u-forged; expect_reject u-forged 7
	srv_stop
}

sc4() { # root configured, issuing sub-CA has no CRL: the leaf needs its issuer's CRL
	reset_conf; CA="R S"; CRLS="R"; POLICY="${H[R]}"
	srv_start 4 || return
	expect_marker 1
	probe s-ok s-ok; expect_reject s-ok 3
	srv_stop
}

sc5() { # three levels R2 -> P -> I
	reset_conf; CA="R2 P I"; CRLS="P"; POLICY="${H[P]}"
	SC=5a; srv_start 5a || return
	expect_marker 1
	probe i-ok i-ok; expect_reject i-ok 3
	srv_stop
	reset_conf; CA="R2 P I"; CRLS="I"; POLICY="${H[I]}"
	SC=5b; srv_start 5b || return
	expect_marker 1
	probe i-ok i-ok; expect_accept i-ok
	probe i-rev i-rev; expect_reject i-rev 23 regr
	srv_stop
	reset_conf; CA="R2 P I"; CRLS="P I"; POLICY="${H[P]} ${H[I]}"
	SC=5c; srv_start 5c || return
	expect_marker 2
	probe i-ok i-ok; expect_accept i-ok
	probe i-rev i-rev; expect_reject i-rev 23 regr
	srv_stop
}

sc6() { # only R is trusted, the client sends its leaf + S
	reset_conf; CA="R"; POLICY="${H[R]}"
	SC=6a; srv_start 6a || return
	expect_marker 1
	probe s-ok+S s-ok S; expect_reject s-ok+S 3
	srv_stop
	reset_conf; CA="R"; POLICY="${H[U]}"
	SC=6b; srv_start 6b || return
	expect_marker 1
	probe s-ok+S s-ok S; expect_accept_unconf s-ok+S S
	srv_stop
}

sc7() { # extra CA certificates sent by the client, off the path
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	srv_start 7 || return
	expect_marker 1
	probe s-rev+U s-rev U; expect_reject s-rev+U 23 regr
	probe u-ok+S u-ok S; expect_accept_unconf u-ok+S U
	srv_stop
}

sc8() { # R re-issued with the same key: the policy line of R covers R'
	reset_conf; CA="Rre S"; POLICY="${H[R]}"
	SC=8a; srv_start 8a || return
	expect_marker 1
	probe s-ok s-ok; expect_reject s-ok 3
	srv_stop
	reset_conf; CA="Rre S"; POLICY="${H[U]}"
	SC=8b; srv_start 8b || return
	expect_marker 1
	probe s-ok s-ok; expect_accept_unconf s-ok S
	srv_stop
}

sc9() { # path through the cross certificate S' (under U, not configured) still matches S by SPKI
	reset_conf; CA="R U"; CRLS="S"; POLICY="${H[S]}"
	SC=9a; srv_start 9a || return
	expect_marker 1
	probe s-rev+Sx s-rev Sx; expect_reject s-rev+Sx 23 regr
	srv_stop
	reset_conf; CA="R U"; POLICY="${H[S]}"
	SC=9b; srv_start 9b || return
	expect_marker 1
	probe s-ok+Sx s-ok Sx; expect_reject s-ok+Sx 3
	srv_stop
}

sc10() { # configured CA, CRL expired / not yet valid
	reset_conf; CA="R S"; CRLS="S-expired"; POLICY="${H[S]}"
	SC=10a; srv_start 10a || return
	expect_marker 1
	probe s-ok s-ok; expect_reject s-ok 12
	srv_stop
	reset_conf; CA="R S"; CRLS="S-notyet"; POLICY="${H[S]}"
	SC=10b; srv_start 10b || return
	expect_marker 1
	probe s-ok s-ok; expect_reject s-ok 11
	srv_stop
}

sc11() { # malformed lines are configuration errors
	local hs=${H[S]} i line
	local -a bad=("zz${hs:2} crl" "${hs:1} crl" "$hs crl bogus" "$hs" "$hs crl=1" "" "   " "$hs CRL" "$hs crl crl")
	local -a name=(not-hex 63-chars unknown-flag no-flags flag-value empty spaces-only upper-case-flag crl-twice)
	for i in "${!bad[@]}"; do
		reset_conf; CA="R S"; CRLS="S"; RAW_POLICY=("${bad[$i]}")
		xc "11-$i"
		if [ "$XC_RC" != 0 ] && grep -qF "ca_policy \"${bad[$i]}\"" "$XC_LOG"; then
			row "${name[$i]}" "-XC fails naming the line" "exit $XC_RC: $(grep -F 'ca_policy "' "$XC_LOG" | head -1 | sed 's/.*ca_policy/ca_policy/')" PASS
		else
			row "${name[$i]}" "-XC fails naming the line" "exit $XC_RC" FAIL
		fi
	done
	reset_conf; CA="R S"; CRLS="S"; RAW_POLICY=("$hs crl" "${hs^^} crl")
	xc 11-dup
	if [ "$XC_RC" != 0 ] && grep -q 'already listed' "$XC_LOG"; then
		row duplicate "-XC fails naming the line" "exit $XC_RC: $(grep -F 'ca_policy "' "$XC_LOG" | head -1 | sed 's/.*ca_policy/ca_policy/')" PASS
	else
		row duplicate "-XC fails naming the line" "exit $XC_RC" FAIL
	fi
	# a tab is whitespace like a space: valid
	reset_conf; CA="R S"; CRLS="S"; RAW_POLICY=("${hs}"$'\t'"crl")
	xc 11-tab
	local m; m=$(marker_in "$XC_LOG")
	if [ "$XC_RC" = 0 ] && [ "$m" = "tls: ca_policy: 1 entries in tls-config tls-nac;" ]; then row tab-separator "-XC exit 0 + marker 1" "exit $XC_RC, $m" PASS
	else row tab-separator "-XC exit 0 + marker 1" "exit $XC_RC, ${m:-no marker}" FAIL; fi
}

sc12() { # delta CRL (the fork's delta fix) with a configured CA
	reset_conf; CA="R S"; CRLS="S-base S-delta"; POLICY="${H[S]}"
	srv_start 12 || return
	expect_marker 1
	probe s-drev s-drev; expect_reject s-drev 23 regr
	probe s-ok s-ok; expect_accept s-ok
	srv_stop
}

sc13() { # ca_policy without check_crl: warning, CRLs not checked at all
	reset_conf; CA="R S"; CRLS="S"; POLICY="${H[S]}"; CHECK_CRL=no
	srv_start 13 || return
	expect_marker 1
	if grep -q 'ca_policy has no effect without check_crl = yes' "$SLOG"; then row start-warn "WARN at startup" "present" PASS
	else row start-warn "WARN at startup" "absent" FAIL; fi
	probe s-rev s-rev; expect_accept s-rev
	srv_stop
}

sc14() { # PEAP on the same tls-config
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"; PEAP=1
	srv_start 14 || return
	expect_marker 1
	probe peap peap; expect_accept peap
	srv_stop
}

wait_until() { local t=$1; while [ "$(now)" -lt "$t" ]; do sleep 5; done; }

sc15() { # SLOW: the CRL is re-read with the store, and the WARN memory is reset with it
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"; RELOAD=300
	srv_start 15 || return
	expect_marker 1
	probe u-ok-1 u-ok; expect_accept_unconf u-ok-1 U
	probe s-ok-1 s-ok; expect_accept s-ok-1
	cp "$P/crl/S-revok.pem" "$D/crl/S.pem"
	openssl rehash "$D/crl" >/dev/null 2>&1
	probe s-ok-2 s-ok; row s-ok-before-reload "measured" "$(got)" RECORD
	wait_until $((T0 + 285))
	probe u-ok-pre u-ok
	local w0; w0=$(warns_for "${H[U]}")
	if [ "$V" = ACCEPT ] && [ "$w0" = 1 ]; then row u-ok-before-reload "Accept, still 1 WARN for U" "$(got) warn=$w0" PASS
	else row u-ok-before-reload "Accept, still 1 WARN for U" "$(got) warn=$w0" FAIL; fi
	wait_until $((T0 + 310))
	probe s-ok-3 s-ok
	if ! grep -q 'Flushing X509 store' "$SLOG"; then row reload "Flushing X509 store" "absent" INCONCLUSIVE; srv_stop; return; fi
	expect_reject s-ok-after-reload 23 regr
	probe u-ok-2 u-ok; expect_accept_unconf u-ok-after-reload U
	local w; w=$(warns_for "${H[U]}")
	if [ "$w" = 2 ]; then row warn-again "2nd WARN for U after the reload" "$w" PASS; else row warn-again "2nd WARN for U after the reload" "$w" FAIL; fi
	srv_stop
}

sc16() { # SLOW, measurement: a CRL file appearing in ca_path without a store rebuild
	reset_conf; CA="R S"; POLICY="${H[S]}"; RELOAD=300
	srv_start 16 || return
	expect_marker 1
	probe s-ok s-ok; expect_reject s-ok-no-crl 3
	cp "$P/crl/S.pem" "$D/crl/S.pem"
	openssl rehash "$D/crl" >/dev/null 2>&1
	probe s-rev-1 s-rev
	row new-crl-immediately "measured (23 = picked up at once, 3 = only after the reload)" "$(got)" RECORD
	wait_until $((T0 + 310))
	probe s-rev-2 s-rev
	if ! grep -q 'Flushing X509 store' "$SLOG"; then row reload "Flushing X509 store" "absent" INCONCLUSIVE; srv_stop; return; fi
	expect_reject s-rev-after-reload 23 regr
	srv_stop
}

sc17() { # SPKI hash: C (daemon WARN) = asn1parse reference = spki.py (raw TBS slice)
	reset_conf; CA="R U E PSS Nn"; POLICY="${H[SRV]}"
	srv_start 17 || return
	expect_marker 1
	local fx=$W/spki-fixtures pair ca leaf c py
	mkdir -p "$fx"
	printf 'name\tfile\tc_daemon\tref_asn1parse\tpy_raw_tbs\n' >"$fx/spki-hashes.tsv"
	for pair in R:r-ok U:u-ok E:e-ok PSS:pss-ok Nn:n-ok; do
		ca=${pair%%:*}; leaf=${pair#*:}
		probe "$leaf" "$leaf"
		c=$(grep -o 'CRL not checked for .*issuer key sha256:[0-9a-f]*' "$PLOG" | sed 's/.*sha256://' | head -1)
		py=$(py_spki "$(cert "$ca")")
		cp "$(cert "$ca")" "$fx/$ca.pem"
		printf '%s\t%s\t%s\t%s\t%s\n' "$ca" "$ca.pem" "${c:-none}" "${H[$ca]}" "$py" >>"$fx/spki-hashes.tsv"
		if [ "$V" = ACCEPT ] && [ -n "$c" ] && [ "$c" = "${H[$ca]}" ] && [ "$c" = "$py" ]; then
			row "spki-$ca" "C = asn1parse = py" "C=${c:0:16}... ref=${H[$ca]:0:16}... py=${py:0:16}..." PASS
		else
			row "spki-$ca" "C = asn1parse = py" "$V C=${c:-none} ref=${H[$ca]:0:16}... py=${py:0:16}..." FAIL
		fi
	done
	srv_stop
}

sc18() { # non-standard SPKI in the policy, CRL expired: Reject 12 (not "unconfigured")
	reset_conf; CA="E PSS Nn"; CRLS="E-expired PSS-expired N-expired"; POLICY="${H[E]} ${H[PSS]} ${H[Nn]}"
	srv_start 18 || return
	expect_marker 3
	probe e-ok e-ok; expect_reject e-ok-ec-compressed 12
	probe pss-ok pss-ok; expect_reject pss-ok-rsa-pss 12
	probe n-ok n-ok; expect_reject n-ok-rsa-no-null 12
	srv_stop
}

sc19() { # certificate attributes exist in post-auth on an Accept whose CRL error was cleared
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	srv_start 19 || return
	expect_marker 1
	local pair leaf issuer rm re='serial=<[0-9a-f]+>'
	for pair in "u-ok:CAPOL Root U" "s-ok:CAPOL Issuing S"; do
		leaf=${pair%%:*}; issuer=${pair#*:}
		probe "$leaf" "$leaf"
		rm=$(grep -o 'Reply-Message := "capol[^"]*"\|Reply-Message = "capol[^"]*"' "$PLOG" | tail -1)
		if [ "$V" = ACCEPT ] && [[ $rm == *"issuer=</CN=$issuer>"* ]] && [[ $rm =~ $re ]]; then
			row "$leaf-attrs" "Accept + TLS-Client-Cert-Issuer/-Serial" "$V ${rm#*:= }" PASS
		else
			row "$leaf-attrs" "Accept + TLS-Client-Cert-Issuer/-Serial" "$V ${rm:-no Reply-Message}" FAIL
		fi
	done
	srv_stop
}

sc20() { # recorded: the upstream "ocsp" section on, U (not listed) with an OCSP responder
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	local oport=$(( $(port_of 20) + 5 ))
	EXTRA_TLS="		ocsp {
			enable = yes
			override_cert_url = yes
			url = \"http://127.0.0.1:$oport/\"
			use_nonce = yes
			timeout = 5
			softfail = no
		}"
	mkdir -p "$W/sc-20-ocsp"
	openssl ocsp -index "$P/U/db/index" -port "$oport" -rsigner "$P/leaf/ocsp-u.pem" -rkey "$P/leaf/ocsp-u.key" \
		-CA "$P/U/cert.pem" -ignore_err >"$W/sc-20-ocsp/ocsp.log" 2>&1 &
	local opid=$!
	sleep 1
	srv_start 20 || { kill $opid 2>/dev/null; return; }
	expect_marker 1
	probe u-ok u-ok
	row u-ok-ocsp "recorded as is" \
		"$(got); $(grep -iE 'ocsp' "$PLOG" | grep -viE 'Creating attributes|^\s*$' | sed 's/^([0-9]*) //' | sort -u | head -4 | tr '\n' ' ')" RECORD
	srv_stop
	kill $opid 2>/dev/null; wait $opid 2>/dev/null
}

sc21() { # a loop of cross-certificates above the chain: the walk ends, the rule applies
	reset_conf; CA="Ax Bx"; POLICY="${H[S]}"
	SC=21a; srv_start 21a || return
	expect_marker 1
	probe x-ok x-ok; expect_accept_unconf x-ok A
	srv_stop
	reset_conf; CA="Ax Bx"; POLICY="${H[B]}"
	SC=21b; srv_start 21b || return
	expect_marker 1
	probe x-ok x-ok; expect_reject x-ok 3
	srv_stop
}

sc22() { # a root re-issued under the same DN with a new key; Sq has no AKID: every candidate counts
	reset_conf; CA="Qold Qnew Sq"; POLICY="${H[Qnew]}"
	SC=22a; srv_start 22a || return
	expect_marker 1
	probe q-ok q-ok; expect_reject q-ok-old-first 3
	srv_stop
	reset_conf; CA="Qnew Qold Sq"; POLICY="${H[Qnew]}"
	SC=22b; srv_start 22b || return
	expect_marker 1
	probe q-ok q-ok; expect_reject q-ok-new-first 3
	srv_stop
	reset_conf; CA="Qold Qnew Sq"; POLICY="${H[U]}"
	SC=22c; srv_start 22c || return
	expect_marker 1
	probe q-ok q-ok; expect_accept_unconf q-ok-control Sq
	srv_stop
}

sc23() { # a chain of one: the client certificate itself is trusted
	reset_conf; CA="Lu"; POLICY="${H[S]}"
	SC=23a; srv_start 23a || return
	expect_marker 1
	probe u-ok u-ok
	local w; w=$(warns_direct "${H[Lu]}")
	if [ "$V" = ACCEPT ] && [ "$w" = 1 ]; then row u-ok-direct "Accept + WARN 'trusted directly' with the leaf key" "$(got) warn=$w" PASS
	else row u-ok-direct "Accept + WARN 'trusted directly' with the leaf key" "$(got) warn=$w" FAIL; fi
	srv_stop
	reset_conf; CA="Lu U"; POLICY="${H[U]}"
	SC=23b; srv_start 23b || return
	expect_marker 1
	probe u-ok u-ok; expect_reject_any u-ok-direct-under-listed-U "3 33"
	srv_stop
}

sc24() { # 20 clients at once: right verdicts, exactly one WARN
	reset_conf; CA="R S U"; CRLS="S"; POLICY="${H[S]}"
	srv_start 24 || return
	expect_marker 1
	local i leaf pids="" ok_u=0 bad_u=0 rej_s=0 bad_s=0 w e23
	for i in $(seq 1 20); do
		leaf=u-ok; [ $((i % 4)) = 0 ] && leaf=s-rev
		eapol_conf "par$i" "$leaf"
		timeout "$ET_TO" eapol_test -c "$D/par$i.eapol.conf" -a 127.0.0.1 -p "$PORT" -s testing123 -t "$ET_T" \
			>"$D/par$i.eapol.log" 2>&1 &
		pids+=" $!"
	done
	wait $pids
	sleep 0.5
	for i in $(seq 1 20); do
		if grep -q '^SUCCESS' "$D/par$i.eapol.log"; then
			if [ $((i % 4)) = 0 ]; then bad_s=$((bad_s + 1)); else ok_u=$((ok_u + 1)); fi
		else
			if [ $((i % 4)) = 0 ]; then rej_s=$((rej_s + 1)); else bad_u=$((bad_u + 1)); fi
		fi
	done
	w=$(warns_for "${H[U]}")
	e23=$(grep -c 'OpenSSL says error 23' "$SLOG")
	if [ "$ok_u" = 15 ]; then row parallel-u-ok "15 x u-ok Accept" "$ok_u Accept, $bad_u Reject" PASS
	else row parallel-u-ok "15 x u-ok Accept" "$ok_u Accept, $bad_u Reject" FAIL; fi
	if [ "$rej_s" = 5 ] && [ "$e23" -ge 5 ]; then row parallel-s-rev "5 x s-rev Reject 23" "$rej_s Reject, $bad_s Accept, error-23 lines $e23" PASS
	else row parallel-s-rev "5 x s-rev Reject 23" "$rej_s Reject, $bad_s Accept, error-23 lines $e23" FAIL; fi
	if [ "$w" = 1 ]; then row parallel-warn "exactly 1 WARN for U" "$w" PASS; else row parallel-warn "exactly 1 WARN for U" "$w" FAIL; fi
	srv_stop
}

# ---- driver -----------------------------------------------------------------------------------
say "radiusd: $("$RADIUSD" -v 2>/dev/null | head -1)"
say "openssl: $(openssl version)"
rm -f "$W"/res-*.tsv "$W/times.tsv"
run_sc() {
	local s=$1 t
	SC=$s; t=$(now)
	say "scenario $s"
	"sc$s"
	printf '%s\t%s\n' "$s" $(( $(now) - t )) >>"$W/times.tsv"
}
BG=""
for s in $SCEN; do
	case $s in
	15|16) run_sc "$s" >/dev/null & BG+=" $!" ;;
	esac
done
for s in $SCEN; do
	case $s in
	15|16) ;;
	*) run_sc "$s" ;;
	esac
done
[ -n "$BG" ] && { say "waiting for the SLOW scenarios"; wait $BG; }

# ---- summary ----------------------------------------------------------------------------------
printf 'scenario\tcase\texpected\tactual\tverdict\n' >"$W/results.tsv"
for s in $ALL; do
	for f in "$W/res-$s.tsv" "$W/res-${s}a.tsv" "$W/res-${s}b.tsv" "$W/res-${s}c.tsv"; do
		[ -f "$f" ] && cat "$f" >>"$W/results.tsv"
	done
done
{
	echo "| # | case | expected | actual | verdict |"
	echo "|---|---|---|---|---|"
	tail -n +2 "$W/results.tsv" | awk -F'\t' '{gsub(/\|/, "\\|"); printf "| %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5}'
	echo
	echo "seconds per scenario: $(sort -n "$W/times.tsv" | awk '{printf "%s=%s ", $1, $2}')"
} >"$W/summary.md"
P_=$(awk -F'\t' '$5=="PASS"' "$W/results.tsv" | wc -l)
F_=$(awk -F'\t' '$5=="FAIL"' "$W/results.tsv" | wc -l)
I_=$(awk -F'\t' '$5=="INCONCLUSIVE"' "$W/results.tsv" | wc -l)
R_=$(awk -F'\t' '$5=="RECORD"' "$W/results.tsv" | wc -l)
say "TOTAL: PASS $P_, FAIL $F_, INCONCLUSIVE $I_, RECORD $R_"
[ "$F_" -gt 0 ] && exit 1
[ "$I_" -gt 0 ] && exit 2
exit 0
