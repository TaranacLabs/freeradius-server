# Per-CA OCSP scenarios (30-49) of the ca_policy harness.  Sourced by run.sh, which provides
# P, W, H[], cert, row, reset_conf, gen_conf, srv_start/srv_stop, probe, eapol_conf, xc, marker_in.
#
# Network: everything is on 127.0.0.1 (the harness runs with --network none).
#   17881 responder, the AIA of the test leaves (http://ocsp.capol.test:17881/aia, the name is put
#         in /etc/hosts); 17882 / 17883 responder, "ocsp_url" A / B
#   17891 closed (refused), 17892 black hole (accept queue full), 17893 silent (accepts, never answers)
#   DNS: /etc/resolv.conf is pointed at a stub on 127.0.0.1:53 (NXDOMAIN or silent), restored after
#
# Verdict rules:
#   Reject <verdict>  eapol_test fails AND the probe's slice of the server log has
#                     "ocsp verdict <verdict>" (with the class for "failed")
#   Accept, good      eapol_test succeeds, the slice has "ocsp verdict good" AND the responder
#                     logged >= 1 request during the probe
#   Accept, not needed eapol_test succeeds, no verdict line AND 0 requests
OA=http://127.0.0.1:17882/a
OB=http://127.0.0.1:17883/b
OD=$W/ocsp
OCSP_OK=1
python3 -c 'import cryptography' 2>/dev/null || OCSP_OK=0
RPID=""

ocsp_hosts() { # the AIA name of the test leaves
	grep -q 'ocsp.capol.test' /etc/hosts 2>/dev/null && return 0
	echo "127.0.0.1 ocsp.capol.test pki.capol.test" >>/etc/hosts 2>/dev/null
	grep -q 'ocsp.capol.test' /etc/hosts 2>/dev/null
}

need_ocsp() {
	if [ "$OCSP_OK" != 1 ]; then row prerequisites "python3 with cryptography" "missing" INCONCLUSIVE; return 1; fi
	if ! ocsp_hosts; then row prerequisites "ocsp.capol.test in /etc/hosts" "cannot write /etc/hosts" INCONCLUSIVE; return 1; fi
	[ -n "$RPID" ] && kill -0 "$RPID" 2>/dev/null && return 0
	mkdir -p "$OD"; : >"$OD/requests.log"; echo '{}' >"$OD/state.json"
	python3 -I "$HERE/ocsp_responder.py" "$P" "$OD/state.json" "$OD/requests.log" 17881 17882 17883 >"$OD/responder.log" 2>&1 &
	RPID=$!
	local i
	for i in $(seq 1 50); do grep -q 'responder up' "$OD/responder.log" && return 0; sleep 0.1; done
	row prerequisites "OCSP responder up" "$(tail -3 "$OD/responder.log" | tr '\n' ' ')" INCONCLUSIVE
	return 1
}
ocsp_stop() { [ -n "$RPID" ] && { kill "$RPID" 2>/dev/null; wait "$RPID" 2>/dev/null; RPID=""; }; }

ostate() { # ostate '<json>': the responder's behaviour from the next request on
	printf '%s\n' "$1" >"$OD/state.json.tmp" && mv "$OD/state.json.tmp" "$OD/state.json"
}
nreq() { wc -l <"$OD/requests.log"; }
lastreq() { tail -1 "$OD/requests.log"; }
req_field() { # req_field <json key>: the value in the last request
	python3 -I -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2]))' "$(lastreq)" "$1" 2>/dev/null
}

tnow() { date +%s.%N; }
tdiff() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.2f", b-a}'; }

# oprobe <label> <leaf> [extra CA ...]: probe + VERD (verdict words), VLINE, NREQ (requests during it), DT
oprobe() {
	local r0 t0
	r0=$(nreq); t0=$(tnow)
	probe "$@"
	DT=$(tdiff "$t0" "$(tnow)")
	NREQ=$(( $(nreq) - r0 ))
	VLINE=$(grep -o 'ocsp verdict .*' "$PLOG" | head -1)
	VERD=$(sed -n 's/^ocsp verdict \([a-z]*\)\(: \|; \)\?.*/\1/p' <<<"$VLINE")
	[ "$VERD" = failed ] && VERD="failed $(sed -n 's/^ocsp verdict failed \([a-z]*\):.*/\1/p' <<<"$VLINE")"
}
ogot() { echo "$V verdict=${VERD:-none} req=$NREQ ${DT}s${VLINE:+ | ${VLINE:0:170}}"; }

# expect_o <case> <good|none|revoked|unknown|failed <class>> <requests: N | +> [detail substring]
expect_o() {
	local c=$1 want=$2 nr=$3 sub=${4:-} ok=1
	case $want in
	good) [ "$V" = ACCEPT ] && [ "$VERD" = good ] || ok=0 ;;
	none) [ "$V" = ACCEPT ] && [ -z "$VERD" ] || ok=0 ;;
	*)    [ "$V" = REJECT ] && [ "$VERD" = "$want" ] || ok=0 ;;
	esac
	if [ "$nr" = + ]; then [ "$NREQ" -ge 1 ] || ok=0; else [ "$NREQ" = "$nr" ] || ok=0; fi
	[ -n "$sub" ] && { grep -qF -- "$sub" <<<"$VLINE" || ok=0; }
	local x="${want/none/Accept, OCSP not needed}"; x="${x/good/Accept, good}"
	[ "$want" != good ] && [ "$want" != none ] && x="Reject $want"
	x+=", requests $nr${sub:+, '$sub'}"
	if [ "$ok" = 1 ]; then row "$c" "$x" "$(ogot)" PASS; else row "$c" "$x" "$(ogot)" FAIL; fi
}
# expect_time <case> <max seconds> : PASS if DT <= max (RECORD under valgrind / ASan)
expect_time() {
	if [ "$VALGRIND" = 1 ] || [ "${ASAN:-0}" = 1 ]; then row "$1" "measured (instrumented)" "${DT}s" RECORD; return; fi
	if awk -v t="$DT" -v m="$2" 'BEGIN{exit !(t <= m)}'; then row "$1" "<= $2 s" "${DT}s" PASS
	else row "$1" "<= $2 s" "${DT}s" FAIL; fi
}

# ocsp_conf: the usual base of the OCSP scenarios
ocsp_conf() { reset_conf; CHECK_CRL=no; CA="${1:-R S}"; shift; RAW_POLICY=("$@"); }

# par <prefix> <n> <leaf> : n eapol_test at once; PAR_OK, PAR_REJ, PAR_SLOG (server log slice)
par() {
	local pre=$1 n=$2 leaf=$3 i pids="" n0
	n0=$(wc -l <"$SLOG")
	for i in $(seq 1 "$n"); do
		eapol_conf "$pre$i" "$leaf"
		timeout "$ET_TO" eapol_test -c "$D/$pre$i.eapol.conf" -a 127.0.0.1 -p "$PORT" -s testing123 -t "$ET_T" \
			>"$D/$pre$i.eapol.log" 2>&1 &
		pids+=" $!"
	done
	wait $pids
	sleep 0.3
	PAR_OK=0; PAR_REJ=0
	for i in $(seq 1 "$n"); do
		if grep -q '^SUCCESS' "$D/$pre$i.eapol.log"; then PAR_OK=$((PAR_OK + 1)); else PAR_REJ=$((PAR_REJ + 1)); fi
	done
	PAR_SLOG=$D/$pre.srv.log
	tail -n +$((n0 + 1)) "$SLOG" >"$PAR_SLOG"
}
# vcount <verdict words> [log]: verdict lines (not the "Login incorrect" copy of a reject)
vcount() { grep "ocsp verdict $1" "${2:-$PAR_SLOG}" | grep -vc 'Login incorrect'; }

# timed side probes while a storm runs: PEAP (EAP) and MAB (plain PAP)
peap_probe() { # peap_probe <label>: PT seconds, PV
	local t0
	eapol_conf "$1" peap
	t0=$(tnow)
	if timeout "$ET_TO" eapol_test -c "$D/$1.eapol.conf" -a 127.0.0.1 -p "$PORT" -s testing123 -t "$ET_T" \
		>"$D/$1.eapol.log" 2>&1 && grep -q '^SUCCESS' "$D/$1.eapol.log"; then PV=ACCEPT; else PV=REJECT; fi
	PT=$(tdiff "$t0" "$(tnow)")
}
mab_probe() { # mab_probe <label>: PT seconds, PV
	local t0
	t0=$(tnow)
	if printf 'User-Name = "00-11-22-33-44-55"\nUser-Password = "00-11-22-33-44-55"\n' \
		| timeout 10 radclient -D "$DICTDIR" -t 3 -r 1 "127.0.0.1:$PORT" auth testing123 >"$D/$1.mab.log" 2>&1 \
		&& grep -q 'Access-Accept' "$D/$1.mab.log"; then PV=ACCEPT; else PV=REJECT; fi
	PT=$(tdiff "$t0" "$(tnow)")
}

# ---- 30: parsing ----------------------------------------------------------------------------
xc_ok() { # xc_ok <case> <N> <warn|nowarn>: config from RAW_POLICY / EXTRA_TLS / CHECK_CRL
	local c=$1 n=$2 w=$3 m g
	xc "30-$c"
	m=$(marker_in "$XC_LOG")
	g="exit $XC_RC, ${m:-no marker}"
	if grep -q 'ca_policy has no effect without check_crl = yes' "$XC_LOG"; then g+=", warn"; else g+=", nowarn"; fi
	if [ "$XC_RC" = 0 ] && [ "$m" = "tls: ca_policy: $n entries in tls-config tls-nac;" ] && [[ $g == *", $w" ]]; then
		row "$c" "-XC exit 0, marker $n, $w" "$g" PASS
	else row "$c" "-XC exit 0, marker $n, $w" "$g; $(grep -m1 -F 'ca_policy "' "$XC_LOG")" FAIL; fi
}
xc_bad() { # xc_bad <case> <substring>
	local c=$1 sub=$2 msg
	xc "30-$c"
	msg=$(grep -m1 -F 'ca_policy "' "$XC_LOG" | sed 's/.*: ca_policy /ca_policy /')
	if [ "$XC_RC" != 0 ] && grep -qF -- "$sub" <<<"$msg"; then row "$c" "-XC fails: '$sub'" "exit $XC_RC: $msg" PASS
	else row "$c" "-XC fails: '$sub'" "exit $XC_RC: ${msg:-<no ca_policy error>}" FAIL; fi
}
sc30() {
	local hs=${H[S]} hu=${H[U]} hr=${H[R]}
	local on="		ocsp {
			enable = yes
		}"
	local off="		ocsp {
			enable = no
		}"
	ocsp_conf "R S" "$hs ocsp"; xc_ok ocsp 1 nowarn
	ocsp_conf "R S U" "$hs crl ocsp" "$hu ocsp ocsp_url=http://pki.example/ocsp" "$hr crl"; CHECK_CRL=yes; xc_ok mixed 3 nowarn
	ocsp_conf "R S" "$hs ocsp_url=http://10.0.0.1:8080/ocsp?a=b ocsp"; xc_ok url-first 1 nowarn
	ocsp_conf "R S" "$hs"$'\t'"ocsp"$'\t'"ocsp_url=http://10.0.0.1/o"; xc_ok tabs 1 nowarn
	ocsp_conf "R S U" "$hs crl ocsp" "$hu ocsp"; xc_ok crl-without-check_crl 2 warn
	ocsp_conf "R S U" "$hs ocsp" "$hu ocsp"; xc_ok ocsp-without-check_crl 2 nowarn
	ocsp_conf "R S" "$hs ocsp ocsp_url=HTTP://Pki.Example/o"; xc_ok scheme-case 1 nowarn
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://[fd00::1]:8080/o"; xc_ok ipv6 1 nowarn
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://pki.example"; xc_ok no-path 1 nowarn
	ocsp_conf "R S" "$hs ocsp"; EXTRA_TLS=$off; xc_ok section-off 1 nowarn
	ocsp_conf "R S" "$hs crl"; CHECK_CRL=yes; EXTRA_TLS=$on; xc_ok crl-with-section-on 1 nowarn
	ocsp_conf "R S" "$hs ocsp_url=http://x/o"; xc_bad url-without-ocsp "flag 'ocsp_url' needs the flag 'ocsp'"
	ocsp_conf "R S" "$hs ocsp ocsp_url=https://x/o"; xc_bad https "https responder URLs are not supported"
	ocsp_conf "R S" "$hs ocsp ocsp_url=HTTPS://x/o"; xc_bad https-case "https responder URLs are not supported"
	ocsp_conf "R S" "$hs ocsp ocsp_url=ldap://x/o"; xc_bad ldap "must start with http://"
	ocsp_conf "R S" "$hs ocsp ocsp_url=pki.example/o"; xc_bad no-scheme "must start with http://"
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://x:99999/o"; xc_bad port-range "cannot parse the responder URL"
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://x:abc/o"; xc_bad port-junk "cannot parse the responder URL"
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://x:0/o"; xc_bad port-0 "has port 0"
	ocsp_conf "R S" "$hs ocsp ocsp_url=http:///o"; xc_bad no-host "needs a host"
	ocsp_conf "R S" "$hs ocsp ocsp_url="; xc_bad empty-url "has an empty URL"
	ocsp_conf "R S" "$hs ocsp ocsp_url"; xc_bad bare-url "needs a value"
	ocsp_conf "R S" "$hs ocsp ocsp"; xc_bad ocsp-twice "flag 'ocsp' given twice"
	ocsp_conf "R S" "$hs ocsp ocsp_url=http://a/ ocsp_url=http://b/"; xc_bad url-twice "flag 'ocsp_url' given twice"
	ocsp_conf "R S" "$hs ocsp=1"; xc_bad ocsp-value "flag 'ocsp' takes no value"
	ocsp_conf "R S" "$hs OCSP"; xc_bad upper-case "unknown flag 'OCSP'"
	ocsp_conf "R S" "$hs"; xc_bad no-flags "(expected 'crl' or 'ocsp')"
	ocsp_conf "R S" "$hs ocsp"; EXTRA_TLS=$on; xc_bad section-on "ca_policy ocsp and the ocsp section are mutually exclusive"
	ocsp_conf "R S U" "$hs crl" "$hu crl ocsp"; CHECK_CRL=yes; EXTRA_TLS=$on; xc_bad section-on-2nd "mutually exclusive"
	ocsp_conf "R S" "$hs ocsp" "$hs crl"; xc_bad duplicate-key "key hash already listed"
}

# ---- 31: the three statuses, responder from the AIA -----------------------------------------
sc31() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp"
	srv_start 31 || return
	expect_marker 1
	ostate '{}'; oprobe good s-aia; expect_o good good 1
	ostate '{"status": {"s-aia": "revoked"}}'; oprobe revoked s-aia; expect_o revoked revoked 1 "reason keyCompromise, revoked at "
	ostate '{"status": {"s-aia": "unknown"}}'; oprobe unknown s-aia; expect_o unknown unknown 1 "the responder does not know the certificate; responder http://ocsp.capol.test:17881/aia"
	srv_stop
}

# ---- 32: which chains are checked; the CertID is about the leaf's issuer ----------------------
sc32() {
	need_ocsp || return
	ocsp_conf "R S U" "${H[S]} ocsp ocsp_url=$OA"
	SC=32a; srv_start 32a || return
	expect_marker 1
	ostate '{}'; oprobe u-not-listed u-ok; expect_o u-not-listed none 0
	srv_stop
	ocsp_conf "R S" "${H[R]} ocsp"
	SC=32b; srv_start 32b || return
	expect_marker 1
	ostate '{}'; oprobe root-listed s-aia; expect_o root-listed good 1
	local iss; iss=$(req_field issuer)
	if [ "$iss" = S ]; then row certid-issuer "CertID issuer = S (the leaf's issuer)" "$iss" PASS; else row certid-issuer "CertID issuer = S" "$iss" FAIL; fi
	# Microsoft profile: the responder serves the issuing CA only, "unauthorized" for others
	ostate '{"serves": ["S"]}'; oprobe ms-serves-issuing s-aia; expect_o ms-serves-issuing good 1
	ostate '{"serves": ["R"]}'; oprobe ms-serves-root-only s-aia; expect_o ms-serves-root-only "failed response" 1 "unauthorized"
	srv_stop
	ocsp_conf "R2 P I" "${H[P]} ocsp ocsp_url=$OA"
	SC=32c; srv_start 32c || return
	expect_marker 1
	ostate '{"serves": ["I"]}'; oprobe three-levels i-ok; expect_o three-levels good 1
	iss=$(req_field issuer)
	if [ "$iss" = I ]; then row certid-issuer-3 "CertID issuer = I" "$iss" PASS; else row certid-issuer-3 "CertID issuer = I" "$iss" FAIL; fi
	ostate '{"serves": ["P"]}'; oprobe three-levels-wrong-ca i-ok; expect_o three-levels-wrong-ca "failed response" 1 "unauthorized"
	srv_stop
}

# ---- 33: where the URL comes from -----------------------------------------------------------
sc33() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=http://127.0.0.1:17882/ovr"
	SC=33a; srv_start 33a || return
	ostate '{}'; oprobe override s-aia; expect_o override good 1
	local pp; pp="$(req_field port)$(req_field path)"
	if [ "$pp" = "17882/ovr" ]; then row override-used "request on 17882/ovr, not the AIA" "$pp" PASS; else row override-used "request on 17882/ovr" "$pp" FAIL; fi
	oprobe cai-only+url s-cai; expect_o cai-only+url good 1
	oprobe no-aia+url s-ok; expect_o no-aia+url good 1
	srv_stop
	ocsp_conf "R S" "${H[S]} ocsp"
	SC=33b; srv_start 33b || return
	ostate '{}'
	oprobe no-aia-no-url s-ok; expect_o no-aia-no-url "failed config" 0 "no OCSP responder URL"
	if grep -qF 'responder none' <<<"$VLINE"; then row responder-none "'; responder none'" "${VLINE: -40}" PASS; else row responder-none "'; responder none'" "$VLINE" FAIL; fi
	oprobe cai-only s-cai; expect_o cai-only "failed config" 0 "no OCSP responder URL"
	oprobe https-only s-https; expect_o https-only "failed config" 0 "no OCSP responder URL"
	oprobe ldap-then-http s-ldap; expect_o ldap-then-http good 1
	pp="$(req_field port)$(req_field path)"
	if [ "$pp" = "17881/aia" ]; then row ldap-then-http-used "the http entry (17881/aia)" "$pp" PASS; else row ldap-then-http-used "17881/aia" "$pp" FAIL; fi
	oprobe ms-layout s-ms; expect_o ms-layout good 1
	row host-header "recorded: Host, Content-Type, method" "$(req_field host_hdr); Content-Type $(req_field ctype); $(req_field method)" RECORD
	srv_stop
}

# ---- 34: no nonce ----------------------------------------------------------------------------
sc34() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp"
	srv_start 34 || return
	ostate '{"nonce": "omit"}'; oprobe no-nonce-responder s-aia; expect_o no-nonce-responder good 1
	local n; n=$(req_field req_nonce)
	if [ "$n" = False ]; then row request-has-no-nonce "req_nonce false" "$n" PASS; else row request-has-no-nonce "req_nonce false" "$n" FAIL; fi
	n=$(req_field hash)
	if [ "$n" = sha1 ]; then row certid-sha1 "SHA-1 CertID" "$n" PASS; else row certid-sha1 "SHA-1 CertID" "$n" FAIL; fi
	srv_stop
}

# ---- 35: unsuccessful answers -----------------------------------------------------------------
sc35() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	srv_start 35 || return
	local rs
	for rs in tryLater:trylater unauthorized:unauthorized internalError:internalerror malformedRequest:malformedrequest sigRequired:sigrequired; do
		ostate "{\"resp_status\": \"${rs%%:*}\"}"; oprobe "${rs%%:*}" s-ok; expect_o "${rs%%:*}" "failed response" 1 "answered ${rs#*:}"
	done
	# OpenSSL 3.5 returns the body of an answer with status >= 400 (and the body is then checked
	# like any answer: here a good, signed one); before 3.5 the status alone fails the exchange
	if [ "$(openssl version | awk '{ split($2, v, "."); print (v[1] > 3 || (v[1] == 3 && v[2] >= 5)) }')" = 1 ]; then
		ostate '{"http_status": 500}'; oprobe http-500 s-ok; expect_o http-500 good 1
	else
		ostate '{"http_status": 500}'; oprobe http-500 s-ok; expect_o http-500 "failed transport" 1 "no HTTP 200"
	fi
	ostate '{"http_status": 500, "body": "garbage"}'; oprobe http-500-not-der s-ok; expect_o http-500-not-der "failed transport" 1
	ostate '{"body": "garbage"}'; oprobe not-der s-ok; expect_o not-der "failed transport" 1
	srv_stop
}

# ---- 36: the signer of the response, and responses for something else ---------------------------------------
sc36() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	srv_start 36 || return
	ostate '{}'; oprobe ca-with-cert s-ok; expect_o ca-with-cert good 1
	ostate '{"include_cert": false}'; oprobe ca-without-cert s-ok; expect_o ca-without-cert good 1
	ostate '{"signer": "ocsp-s-nocheck"}'; oprobe delegate-nocheck s-ok; expect_o delegate-nocheck good 1
	ostate '{"signer": "ocsp-s-nonocheck"}'; oprobe delegate-without-nocheck s-ok; expect_o delegate-without-nocheck good 1
	ostate '{"signer": "ocsp-s-noeku"}'; oprobe delegate-without-eku s-ok; expect_o delegate-without-eku "failed verify" 1
	ostate '{"include_cert": false, "corrupt_sig": true}'; oprobe bad-signature s-ok; expect_o bad-signature "failed verify" 1
	ostate '{"signer": "ocsp-u"}'; oprobe delegate-of-other-ca s-ok; expect_o delegate-of-other-ca "failed verify" 1
	ostate '{"signer": "leaf:s-ok"}'; oprobe leaf-signs s-ok; expect_o leaf-signs "failed verify" 1
	ostate '{"signer": "leaf:s-ok", "include_cert": false}'; oprobe leaf-signs-no-cert s-ok; expect_o leaf-signs-no-cert "failed verify" 1
	ostate '{"other_serial": true}'; oprobe other-serial s-ok; expect_o other-serial "failed verify" 1 "no status for the certificate"
	srv_stop
}

# ---- 37: times -------------------------------------------------------------------------------
sc37() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	srv_start 37 || return
	ostate '{"next_update": -600}'; oprobe next-10min-ago s-ok; expect_o next-10min-ago "failed verify" 1 "not current"
	ostate '{"this_update": -600, "next_update": -120}'; oprobe next-2min-ago s-ok; expect_o next-2min-ago good 1
	ostate '{"this_update": 600}'; oprobe this-in-10min s-ok; expect_o this-in-10min "failed verify" 1 "not current"
	ostate '{"this_update": 120}'; oprobe this-in-2min s-ok; expect_o this-in-2min good 1
	ostate '{"this_update": -3600, "next_update": null}'; oprobe no-next-1h-old s-ok; expect_o no-next-1h-old "failed verify" 1 "nextUpdate none"
	ostate '{"this_update": -120, "next_update": null}'; oprobe no-next-2min-old s-ok; expect_o no-next-2min-old good 1
	srv_stop
}

# ---- 38: network failures, timed ---------------------------------------------------------------
STUBS=""
stub() { # stub <kind> <args...>: start net_stub.py, wait for "ready"
	local f=$OD/stub-$1-$$-$RANDOM.log i
	python3 -I "$HERE/net_stub.py" "$@" >"$f" 2>&1 &
	STUBS+=" $!"
	for i in $(seq 1 50); do grep -q 'ready\|NOT a black hole' "$f" && break; sleep 0.1; done
	STUB_MSG=$(head -1 "$f")
}
stubs_stop() { [ -n "$STUBS" ] && { kill $STUBS 2>/dev/null; wait $STUBS 2>/dev/null; }; STUBS=""; }
resolv_save() { cp /etc/resolv.conf "$OD/resolv.conf.saved" 2>/dev/null; }
resolv_set() { printf '%s\n' "$@" >/etc/resolv.conf 2>/dev/null && grep -qF "$1" /etc/resolv.conf; }
resolv_restore() { [ -f "$OD/resolv.conf.saved" ] && cat "$OD/resolv.conf.saved" >/etc/resolv.conf 2>/dev/null; }

net_case() { # net_case <sub> <case> <url> <max s> [detail]
	local sub=$1 c=$2 url=$3 max=$4 det=${5:-}
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$url"
	SC=38$sub; srv_start "38$sub" || return
	oprobe "$c" s-ok; expect_o "$c" "failed transport" "${NREQ_WANT:-0}" "$det"
	expect_time "$c-time" "$max"
	row "$c-seconds" "measured" "${DT}s (eapol_test, whole EAP-TLS)" RECORD
	srv_stop
}
sc38() {
	need_ocsp || return
	ostate '{}'
	# the baseline: a good answer, the same way
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	SC=38a; srv_start 38a || return
	oprobe baseline-good s-ok; expect_o baseline-good good 1
	row baseline-seconds "measured" "${DT}s" RECORD
	srv_stop
	net_case b refused http://127.0.0.1:17891/x 5.5 "cannot connect"
	stub blackhole 17892
	if [[ $STUB_MSG == *ready* ]]; then net_case c black-hole http://127.0.0.1:17892/x 4.5
	else row black-hole "a black hole" "$STUB_MSG" INCONCLUSIVE; fi
	stub silent 17893
	net_case d silent http://127.0.0.1:17893/x 4.5
	stubs_stop
	ostate '{"drip": 0.5}'
	NREQ_WANT=1 net_case e slow-drip "$OA" 4.5
	ostate '{}'
	resolv_save
	stub dns nxdomain 53
	if resolv_set "nameserver 127.0.0.1" "options timeout:1 attempts:1"; then
		net_case f nxdomain http://missing.capol.test:17882/x 5.5 "cannot connect"
	else row nxdomain "resolv.conf writable" "no" INCONCLUSIVE; fi
	resolv_restore
	stubs_stop
}

# ---- 49: dead DNS, recorded --------------------------------------------------------------------
sc49() {
	need_ocsp || return
	resolv_save
	stub dns silent 53
	if resolv_set "nameserver 127.0.0.1" "options timeout:1 attempts:1"; then
		ocsp_conf "R S" "${H[S]} ocsp ocsp_url=http://dead.capol.test:17882/x"
		SC=49a; srv_start 49a || { resolv_restore; stubs_stop; return; }
		oprobe dns-dead-timeout1 s-ok; expect_o dns-dead-timeout1 "failed transport" 0
		row dns-dead-timeout1-seconds "measured (resolv.conf options timeout:1 attempts:1)" "${DT}s" RECORD
		srv_stop
		resolv_set "nameserver 127.0.0.1"
		SC=49b; srv_start 49b || { resolv_restore; stubs_stop; return; }
		oprobe dns-dead-default s-ok; expect_o dns-dead-default "failed transport" 0
		row dns-dead-default-seconds "measured (musl defaults: timeout 5, attempts 2)" "${DT}s" RECORD
		srv_stop
	else
		row dns-dead "resolv.conf writable" "no" INCONCLUSIVE
	fi
	resolv_restore
	stubs_stop
}

# ---- 39: the limit, against a black hole (8 in flight, 8 waiting) -------------------------------------------------------
sc39() {
	need_ocsp || return
	stub blackhole 17892
	[[ $STUB_MSG == *ready* ]] || { row black-hole "a black hole" "$STUB_MSG" INCONCLUSIVE; stubs_stop; return; }
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=http://127.0.0.1:17892/x"; THREADS=32; PEAP=1
	srv_start 39 || { stubs_stop; return; }
	par storm 20 s-ok &
	local ppid=$! i pt=""
	sleep 0.5
	for i in 1 2 3; do peap_probe "peap$i"; pt+=" $PV:$PT"; done
	wait $ppid
	# par ran in a subshell: count from the log
	PAR_SLOG=$D/storm-all.log; cp "$SLOG" "$PAR_SLOG"
	local tr bu ok=0
	tr=$(vcount 'failed transport'); bu=$(vcount 'failed busy')
	local acc; acc=$(grep -l '^SUCCESS' "$D"/storm*.eapol.log 2>/dev/null | wc -l)
	# 8 in flight time out (transport), 8 wait 1 s for a slot and 4 find no waiting place (busy)
	if [ "$acc" = 0 ] && [ "$tr" = 8 ] && [ "$bu" = 12 ]; then ok=1; fi
	if [ "$VALGRIND" = 1 ] || [ "$ASAN" = 1 ]; then row storm-20 "recorded (instrumented build: arrivals spread out)" "accept=$acc transport=$tr busy=$bu" RECORD
	elif [ "$ok" = 1 ]; then row storm-20 "20 Reject: 8 transport (in flight), 12 busy (8 waited 1 s, 4 at once)" "accept=$acc transport=$tr busy=$bu" PASS
	else row storm-20 "20 Reject: 8 transport, 12 busy" "accept=$acc transport=$tr busy=$bu" FAIL; fi
	ok=1
	for i in $pt; do [ "${i%%:*}" = ACCEPT ] && awk -v t="${i#*:}" 'BEGIN{exit !(t < 1)}' || ok=0; done
	if [ "$VALGRIND" = 1 ] || [ "$ASAN" = 1 ]; then row peap-during-storm "measured (instrumented build)" "$pt" RECORD
	elif [ "$ok" = 1 ]; then row peap-during-storm "3 PEAP Accept, each < 1 s" "$pt" PASS
	else row peap-during-storm "3 PEAP Accept, each < 1 s" "$pt" FAIL; fi
	srv_stop
	stubs_stop
}

# ---- 46: a healthy responder with some latency, 32 at once ------------------------------
sc46() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"; THREADS=32
	srv_start 46 || return
	local bu gd d
	# 32 at once must all pass when the responder answers in 20 ms
	ostate '{"delay": 0.02}'
	par slow 32 s-ok
	bu=$(vcount 'failed busy'); gd=$(vcount good)
	if [ "$PAR_OK" = 32 ] && [ "$bu" = 0 ]; then row slow-32-0.02s "32 Accept, 0 busy (latency 0.02 s)" "accept=$PAR_OK reject=$PAR_REJ good=$gd busy=$bu" PASS
	else row slow-32-0.02s "32 Accept, 0 busy (latency 0.02 s)" "accept=$PAR_OK reject=$PAR_REJ good=$gd busy=$bu" FAIL; fi
	# and how many "busy" a slower one gives (recorded)
	for d in 0 0.05 0.1; do
		ostate "{\"delay\": $d}"
		par "slow${d/./}-" 32 s-ok
		bu=$(vcount 'failed busy'); gd=$(vcount good)
		row "slow-32-${d}s" "recorded: 32 at once, responder latency ${d} s" "accept=$PAR_OK busy=$bu good=$gd" RECORD
	done
	ostate '{}'
	srv_stop
}

# ---- 47: a black hole, 50 at once; MAB and PEAP stay fast --------------------------------
sc47() {
	need_ocsp || return
	stub blackhole 17892
	[[ $STUB_MSG == *ready* ]] || { row black-hole "a black hole" "$STUB_MSG" INCONCLUSIVE; stubs_stop; return; }
	ocsp_conf "R S R2 P I" "${H[S]} ocsp ocsp_url=http://127.0.0.1:17892/x" "${H[I]} ocsp ocsp_url=$OA"; THREADS=32; PEAP=1
	srv_start 47 || { stubs_stop; return; }
	ostate '{}'
	par storm 50 s-ok >/dev/null &
	local ppid=$! i pt="" mt=""
	sleep 0.5
	for i in 1 2 3; do mab_probe "mab$i"; mt+=" $PV:$PT"; peap_probe "peap$i"; pt+=" $PV:$PT"; done
	wait $ppid
	PAR_SLOG=$D/storm-all.log; cp "$SLOG" "$PAR_SLOG"
	local tr bu acc
	tr=$(vcount 'failed transport'); bu=$(vcount 'failed busy')
	acc=$(grep -l '^SUCCESS' "$D"/storm*.eapol.log 2>/dev/null | wc -l)
	# 8 in flight time out (transport); every other check is "busy" (8 after waiting 1 s)
	if [ "$VALGRIND" = 1 ] || [ "$ASAN" = 1 ]; then
		row storm-50 "recorded (instrumented build)" "accept=$acc transport=$tr busy=$bu" RECORD
	elif [ "$acc" = 0 ] && [ "$tr" = 8 ] && [ "$bu" = 42 ]; then
		row storm-50 "50 Reject: 8 transport, 42 busy" "accept=$acc transport=$tr busy=$bu" PASS
	else row storm-50 "50 Reject: 8 transport, 42 busy" "accept=$acc transport=$tr busy=$bu" FAIL; fi
	local ok=1 okp=1
	for i in $mt; do [ "${i%%:*}" = ACCEPT ] && awk -v t="${i#*:}" 'BEGIN{exit !(t < 1)}' || ok=0; done
	for i in $pt; do [ "${i%%:*}" = ACCEPT ] && awk -v t="${i#*:}" 'BEGIN{exit !(t < 1)}' || okp=0; done
	if [ "$VALGRIND" = 1 ] || [ "$ASAN" = 1 ]; then
		row mab-during-storm "measured (instrumented build)" "$mt" RECORD
		row peap-during-storm "measured (instrumented build)" "$pt" RECORD
	else
		if [ "$ok" = 1 ]; then row mab-during-storm "3 MAB Accept, each < 1 s" "$mt" PASS; else row mab-during-storm "3 MAB Accept, each < 1 s" "$mt" FAIL; fi
		if [ "$okp" = 1 ]; then row peap-during-storm "3 PEAP Accept, each < 1 s" "$pt" PASS; else row peap-during-storm "3 PEAP Accept, each < 1 s" "$pt" FAIL; fi
	fi
	# after the storm every slot is back: 4 at once for the other CA all pass
	par after 4 i-ok
	if [ "$PAR_OK" = 4 ]; then row slots-back "4 x i-ok at once Accept" "accept=$PAR_OK" PASS; else row slots-back "4 x i-ok at once Accept" "accept=$PAR_OK reject=$PAR_REJ $(grep -o 'ocsp verdict [a-z ]*' "$PAR_SLOG" | sort | uniq -c | tr '\n' ' ')" FAIL; fi
	srv_stop
	stubs_stop
}

# ---- 48: no slot leaks after many rejects of every kind ------------------------------------
sc48() {
	need_ocsp || return
	ocsp_conf "R S R2 P I U" "${H[S]} ocsp ocsp_url=$OA" "${H[I]} ocsp ocsp_url=$OB" "${H[U]} ocsp"; THREADS=8
	srv_start 48 || return
	local kinds=('{"http_status": 500, "body": "garbage"}|failed transport' '{"body": "garbage"}|failed transport' '{"resp_status": "tryLater"}|failed response'
		'{"signer": "ocsp-s-noeku"}|failed verify' '{"status": {"s-ok": "revoked"}}|revoked' '{"status": {"s-ok": "unknown"}}|unknown')
	local k st want n=${LEAK_N:-100} r bad="" j=0
	for k in "${kinds[@]}"; do
		st=${k%%|*}; want=${k#*|}; j=$((j + 1))
		ostate "$st"
		for r in $(seq 1 $((n / 4))); do par "leak$j-$r-" 4 s-ok >/dev/null; done
	done
	for r in $(seq 1 $((n / 4))); do par "cfg-$r-" 4 u-ok >/dev/null; done
	local nt
	nt=$(grep -c 'ocsp verdict failed config' "$SLOG")
	[ "$nt" -ge "$n" ] || bad+=" config=$nt"
	# each of the two transport kinds adds n lines of its own
	[ "$(vcount 'failed transport' "$SLOG")" -ge $((2 * n)) ] || bad+=" transport=$(vcount 'failed transport' "$SLOG")"
	for want in "failed response" "failed verify" revoked unknown; do
		[ "$(vcount "$want" "$SLOG")" -ge "$n" ] || bad+=" ${want// /_}=$(vcount "$want" "$SLOG")"
	done
	[ "$(vcount 'failed busy' "$SLOG")" = 0 ] || bad+=" busy=$(vcount 'failed busy' "$SLOG")"
	if [ -z "$bad" ]; then row rejects "$n of each kind (transport x2, response, verify, revoked, unknown, config)" "all counted" PASS
	else row rejects "$n of each kind" "short:$bad" FAIL; fi
	ostate '{}'
	par good 4 s-ok
	if [ "$PAR_OK" = 4 ] && [ "$(vcount good)" = 4 ]; then row slots-back "4 x good at once Accept after it all" "accept=$PAR_OK" PASS
	else row slots-back "4 x good at once Accept" "accept=$PAR_OK $(grep -o 'ocsp verdict [a-z ]*' "$PAR_SLOG" | sort | uniq -c | tr '\n' ' ')" FAIL; fi
	srv_stop
}

# ---- 40: CRL and OCSP on the same chain: AND ----------------------------------------------------
sc40() {
	need_ocsp || return
	reset_conf; CA="R S"; CRLS="S"; RAW_POLICY=("${H[S]} crl ocsp ocsp_url=$OA")
	SC=40a; srv_start 40a || return
	expect_marker 1
	ostate '{}'
	oprobe crl-revoked s-rev; expect_reject crl-revoked 23 regr
	if [ "$NREQ" = 0 ]; then row crl-revoked-no-request "0 OCSP requests" "$NREQ" PASS; else row crl-revoked-no-request "0 OCSP requests" "$NREQ" FAIL; fi
	ostate '{"status": {"s-aia": "revoked"}}'; oprobe crl-good-ocsp-revoked s-aia; expect_o crl-good-ocsp-revoked revoked 1
	ostate '{}'; oprobe both-good s-aia; expect_o both-good good 1
	srv_stop
	# the signer's store has no CRL flags, so a response signed by S needs no CRL of R
	reset_conf; CA="R S"; CRLS="S"; RAW_POLICY=("${H[S]} crl ocsp ocsp_url=$OA")
	SC=40c; srv_start 40c || return
	ostate '{}'; oprobe signed-by-S-no-crl-of-R s-ok; expect_o signed-by-S-no-crl-of-R good 1
	srv_stop
	# U has only OCSP while S has crl: U's CRL errors are cleared, then OCSP applies
	reset_conf; CA="R S U"; CRLS="S"; RAW_POLICY=("${H[S]} crl" "${H[U]} ocsp ocsp_url=$OA")
	SC=40d; srv_start 40d || return
	expect_marker 2
	ostate '{}'; oprobe u-ocsp-only u-ok; expect_o u-ocsp-only good 1
	ostate '{"signer": "ocsp-u"}'; oprobe u-ocsp-only-delegate u-ok; expect_o u-ocsp-only-delegate good 1
	srv_stop
}

# ---- 41: the nearest listed CA gives the URL ------------------------------------------------------
sc41() {
	need_ocsp || return
	ocsp_conf "R S" "${H[R]} ocsp ocsp_url=$OA" "${H[S]} ocsp ocsp_url=$OB"
	SC=41a; srv_start 41a || return
	ostate '{}'; oprobe nearest-url s-aia; expect_o nearest-url good 1
	local pp; pp="$(req_field port)$(req_field path)"
	if [ "$pp" = "17883/b" ]; then row nearest-url-used "S's URL (17883/b)" "$pp" PASS; else row nearest-url-used "S's URL (17883/b)" "$pp" FAIL; fi
	srv_stop
	ocsp_conf "R S" "${H[R]} ocsp ocsp_url=$OA" "${H[S]} ocsp"
	SC=41b; srv_start 41b || return
	ostate '{}'; oprobe nearest-without-url s-aia; expect_o nearest-without-url good 1
	pp="$(req_field port)$(req_field path)"
	if [ "$pp" = "17881/aia" ]; then row nearest-without-url-used "the leaf's AIA (17881/aia), not R's URL" "$pp" PASS
	else row nearest-without-url-used "the leaf's AIA (17881/aia)" "$pp" FAIL; fi
	srv_stop
}

# ---- 42: PEAP and TTLS on the same tls-config ------------------------------------------------------
sc42() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"; PEAP=1
	srv_start 42 || return
	ostate '{}'
	oprobe peap peap; expect_o peap none 0
	oprobe ttls ttls; expect_o ttls none 0
	srv_stop
}

# ---- 43: the TLS alert the client gets, recorded ----------------------------------------------------
sc43() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	srv_start 43 || return
	local st c a want
	for st in 'revoked|certificate_revoked|{"status": {"s-ok": "revoked"}}' 'unknown|certificate_unknown|{"status": {"s-ok": "unknown"}}' \
		'failed|certificate_unknown|{"resp_status": "tryLater"}'; do
		c=${st%%|*}; st=${st#*|}; want=${st%%|*}; ostate "${st#*|}"
		oprobe "alert-$c" s-ok
		a=$(grep -o 'send TLS [0-9.]* Alert, fatal [a-z_]*' "$PLOG" | head -1)
		if [ "$V" = REJECT ] && [ "${a##* }" = "$want" ]; then row "alert-$c" "the server sends $want (not internal_error)" "$a" PASS
		else row "alert-$c" "the server sends $want" "${a:-no alert}" FAIL; fi
		row "alert-$c-client" "recorded: what eapol_test logs" "$(grep -iE 'SSL3 alert|TLS: alert|EAP-Failure' "$D/alert-$c.eapol.log" | sort -u | head -2 | tr '\n' ' ')" RECORD
	done
	srv_stop
}

# ---- 44: session resumption skips OCSP, recorded --------------------------------------------------
sc44() {
	need_ocsp || return
	ocsp_conf "R S" "${H[S]} ocsp ocsp_url=$OA"
	CACHE="enable = yes
			lifetime = 24
			persist_dir = \"$W/sc-44-cache\""
	mkdir -p "$W/sc-44-cache"
	srv_start 44 || return
	ostate '{}'
	eapol_conf resume s-ok
	local r0; r0=$(nreq)
	timeout "$ET_TO" eapol_test -r 1 -c "$D/resume.eapol.conf" -a 127.0.0.1 -p "$PORT" -s testing123 -t "$ET_T" >"$D/resume.eapol.log" 2>&1
	row resumed "recorded: 2 authentications (-r 1), OCSP requests" "successes=$(grep -c 'CTRL-EVENT-EAP-SUCCESS' "$D/resume.eapol.log") resumed handshakes=$(grep -c 'Handshake finished - resumed=1' "$D/resume.eapol.log") OCSP requests=$(( $(nreq) - r0 ))" RECORD
	srv_stop
}
