#!/bin/sh
# PKI for the ca_policy harness.  Usage: pki.sh <dir>   (an empty dir; needs openssl >= 3.0, python3)
#
#   R  (RSA)  -> S (EC) -> s-ok, s-rev, s-drev        CRL S revokes s-rev; delta CRL S revokes s-drev
#   R' = R re-issued with the same key (other serial)  -> same SPKI as R
#   S' = S cross-signed by U (same DN, same key)        -> same SPKI as S
#   R  -> r-ok                                         (a leaf straight under R, for SPKI checks)
#   U  (EC, uncompressed, no CRL) -> u-ok, u-expired; u-forged: issuer DN = U, signed by another key
#   R2 -> P -> I -> i-ok, i-rev                       CRL P, CRL I (revokes i-rev)
#   E  (EC, compressed point) -> e-ok                  non-standard SPKI encodings, each with an
#   PSS (RSA-PSS key)        -> pss-ok                 expired CRL; N-nonull is N with the NULL
#   N  (RSA), N-nonull       -> n-ok                   parameters dropped from its SPKI algorithm
#   SRV -> server                                      the server's own chain, never trusted for clients
#
# CRL files go to crl/<name>.pem; the harness copies the ones a scenario needs into its ca_path.
set -eu
P=$1
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$P/leaf" "$P/crl"
cd "$P"

run() { # quiet unless it fails
	if ! "$@" >"$P/.last.log" 2>&1; then echo "pki: FAILED: $*" >&2; cat "$P/.last.log" >&2; exit 1; fi
}

cnf() { # cnf <ca>
	cat >"$1/ca.cnf" <<C
[ req ]
distinguished_name = dn
[ dn ]
[ ca ]
default_ca = this
[ this ]
dir = $P/$1
database = \$dir/db/index
serial = \$dir/db/serial
crlnumber = \$dir/db/crlnumber
new_certs_dir = \$dir/db
certificate = \$dir/cert.pem
private_key = \$dir/key.pem
default_md = sha256
default_days = 825
default_crl_days = 30
policy = pol
unique_subject = no
copy_extensions = none
[ pol ]
commonName = supplied
[ v3_ca ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_root ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_client ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_client_noakid ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = none
authorityKeyIdentifier = none
[ v3_server ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_ocsp ]
basicConstraints = CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = OCSPSigning
[ base_ext ]
freshestCRL = URI:http://example.invalid/delta.crl
[ delta_ext ]
2.5.29.27 = critical,ASN1:INTEGER:BASE_CRL_NUMBER
C
}

newkey() { # newkey <out> rsa|ec|ecc|pss
	case $2 in
	rsa) run openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1" ;;
	ec)  run openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" ;;
	ecc) # the SEC1 form keeps the point compressed, and OpenSSL then encodes the SPKI that way
	     run openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.tmp"
	     run openssl ec -in "$1.tmp" -conv_form compressed -out "$1"; rm -f "$1.tmp" ;;
	pss) run openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out "$1" ;;
	esac
}

mkca() { # mkca <name>
	mkdir -p "$1/db"; : >"$1/db/index"; echo 1000 >"$1/db/serial"; echo 1000 >"$1/db/crlnumber"; cnf "$1"
}

root() { # root <name> <cn> <alg>
	mkca "$1"; newkey "$1/key.pem" "$3"
	run openssl req -x509 -new -key "$1/key.pem" -out "$1/cert.pem" -days 3650 -subj "/CN=$2" \
		-config "$1/ca.cnf" -extensions v3_root -set_serial "0x$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
}

sub() { # sub <name> <cn> <parent> <alg>
	mkca "$1"; newkey "$1/key.pem" "$4"
	run openssl req -new -key "$1/key.pem" -out "$1/csr.pem" -subj "/CN=$2" -config "$1/ca.cnf"
	run openssl ca -batch -config "$3/ca.cnf" -extensions v3_ca -in "$1/csr.pem" -out "$1/cert.pem" -notext -days 1825
}

leaf() { # leaf <ca> <name> [ext] [startdate enddate]
	newkey "leaf/$2.key" ec
	run openssl req -new -key "leaf/$2.key" -out "leaf/$2.csr" -subj "/CN=$2" -config "$1/ca.cnf"
	if [ $# -ge 5 ]; then
		run openssl ca -batch -config "$1/ca.cnf" -extensions "${3:-v3_client}" -in "leaf/$2.csr" -out "leaf/$2.pem" -notext \
			-startdate "$4" -enddate "$5"
	else
		run openssl ca -batch -config "$1/ca.cnf" -extensions "${3:-v3_client}" -in "leaf/$2.csr" -out "leaf/$2.pem" -notext
	fi
}

crl() { # crl <ca> <out-name> [lastupdate nextupdate] [crlexts]
	ca=$1; out=crl/$2.pem; shift 2
	set -- "$@"
	if [ $# -ge 2 ]; then
		lu=$1; nu=$2; shift 2
		run openssl ca -config "$ca/ca.cnf" -gencrl -out "$out" -crl_lastupdate "$lu" -crl_nextupdate "$nu" ${1:+-crlexts "$1"}
	else
		run openssl ca -config "$ca/ca.cnf" -gencrl -out "$out" -crldays 30 ${1:+-crlexts "$1"}
	fi
}

revoke() { run openssl ca -config "$1/ca.cnf" -revoke "leaf/$2.pem"; }

ago()   { date -u -d "@$(( $(date +%s) - $1 ))" +%Y%m%d%H%M%SZ; }
ahead() { date -u -d "@$(( $(date +%s) + $1 ))" +%Y%m%d%H%M%SZ; }

# ---- server --------------------------------------------------------------------------------------
root SRV "CAPOL Server Root" ec
leaf SRV server v3_server
cat leaf/server.pem SRV/cert.pem >leaf/server_chain.pem

# ---- R -> S, R', S' ---------------------------------------------------------------------------------
root R "CAPOL Root R" rsa
sub S "CAPOL Issuing S" R ec
leaf S s-ok
leaf S s-rev
leaf S s-drev
leaf R r-ok
mkdir -p Rre
run openssl req -x509 -new -key R/key.pem -out Rre/cert.pem -days 3000 -subj "/CN=CAPOL Root R" \
	-config R/ca.cnf -extensions v3_root -set_serial 0x4242
root U "CAPOL Root U" ec
leaf U u-ok
leaf U u-expired v3_client "$(ago 864000)" "$(ago 86400)"
mkdir -p Sx
run openssl ca -batch -config U/ca.cnf -extensions v3_ca -in S/csr.pem -out Sx/cert.pem -notext -days 1825
# u-forged: a CA with U's DN but another key, and no AKID so that OpenSSL picks the real U as issuer
root Ufake "CAPOL Root U" ec
leaf Ufake u-forged v3_client_noakid

crl R R
revoke S s-rev
crl S S
crl S S-expired "$(ago 864000)" "$(ago 86400)"
crl S S-notyet "$(ahead 86400)" "$(ahead 864000)"
# base CRL with Freshest CRL, then a delta (Delta CRL Indicator = base number) revoking s-drev
run openssl ca -config S/ca.cnf -gencrl -out crl/S-base.pem -crldays 30 -crlexts base_ext
BASE=$(openssl crl -in crl/S-base.pem -noout -crlnumber | sed 's/.*=//')
sed -i "s/BASE_CRL_NUMBER/$BASE/" S/ca.cnf
revoke S s-drev
run openssl ca -config S/ca.cnf -gencrl -out crl/S-delta.pem -crldays 30 -crlexts delta_ext
# CRL S which also revokes s-ok (store reload scenario)
revoke S s-ok
crl S S-revok

# ---- R2 -> P -> I -------------------------------------------------------------------------------
root R2 "CAPOL Root R2" ec
sub P "CAPOL Policy P" R2 ec
sub I "CAPOL Issuing I" P ec
leaf I i-ok
leaf I i-rev
crl P P
revoke I i-rev
crl I I

# ---- non-standard SPKI encodings ----------------------------------------------------------------
root E "CAPOL Root EC compressed" ecc
leaf E e-ok
crl E E-expired "$(ago 864000)" "$(ago 86400)"
root PSS "CAPOL Root RSA-PSS" pss
leaf PSS pss-ok
crl PSS PSS-expired "$(ago 864000)" "$(ago 86400)"
root N "CAPOL Root RSA no NULL" rsa
leaf N n-ok
crl N N-expired "$(ago 864000)" "$(ago 86400)"
mkdir -p N-nonull
python3 -I "$HERE/spki.py" strip-null N/cert.pem N-nonull/cert.pem

# ---- OCSP responder for U (scenario 20) ---------------------------------------------------------
newkey leaf/ocsp-u.key ec
run openssl req -new -key leaf/ocsp-u.key -out leaf/ocsp-u.csr -subj "/CN=CAPOL OCSP U" -config U/ca.cnf
run openssl ca -batch -config U/ca.cnf -extensions v3_ocsp -in leaf/ocsp-u.csr -out leaf/ocsp-u.pem -notext

# ---- self-checks: the PKI is what the scenarios assume ------------------------------------------
fail() { echo "pki SELF-CHECK FAIL: $*" >&2; exit 1; }
h() { python3 -I "$HERE/spki.py" hash "$1"; }
[ "$(h R/cert.pem)" = "$(h Rre/cert.pem)" ] || fail "R' does not share R's SPKI"
cmp -s R/cert.pem Rre/cert.pem && fail "R' is byte-identical to R"
[ "$(h S/cert.pem)" = "$(h Sx/cert.pem)" ] || fail "S' does not share S's SPKI"
[ "$(openssl x509 -in Sx/cert.pem -noout -issuer)" = "issuer=CN=CAPOL Root U" ] || fail "S' not issued by U"
openssl x509 -in leaf/u-forged.pem -noout -ext authorityKeyIdentifier 2>/dev/null | grep -q keyid && fail "u-forged has an AKID"
cat U/cert.pem >u.pem
openssl verify -no-CApath -CAfile u.pem leaf/u-forged.pem 2>&1 | grep -q 'error 7 ' || fail "u-forged does not fail with error 7"
openssl verify -no-CApath -CAfile u.pem leaf/u-expired.pem 2>&1 | grep -q 'error 10 ' || fail "u-expired does not fail with error 10"
openssl x509 -in PSS/cert.pem -noout -text | grep -q 'Public Key Algorithm: rsassaPss' || fail "PSS root has no RSA-PSS SPKI"
python3 -I "$HERE/spki.py" ecpoint E/cert.pem | grep -qE '^0[23]$' || fail "E root key is not a compressed point"
[ "$(h N/cert.pem)" != "$(h N-nonull/cert.pem)" ] || fail "N-nonull has the same SPKI bytes as N"
python3 -I "$HERE/spki.py" spki-hex N-nonull/cert.pem | grep -qE '^30(82....|81..)300b06092a864886f70d01010103' || fail "N-nonull SPKI still has NULL params"
openssl verify -no-CApath -CAfile N-nonull/cert.pem leaf/n-ok.pem 2>&1 | grep -q ': OK$' || fail "n-ok does not verify under N-nonull"
openssl verify -no-CApath -CAfile PSS/cert.pem leaf/pss-ok.pem 2>&1 | grep -q ': OK$' || fail "pss-ok does not verify"
openssl verify -no-CApath -CAfile E/cert.pem leaf/e-ok.pem 2>&1 | grep -q ': OK$' || fail "e-ok does not verify"
cat R/cert.pem S/cert.pem >rs.pem
openssl verify -no-CApath -CAfile rs.pem -crl_check -CRLfile crl/S-base.pem -CRLfile crl/S-delta.pem leaf/s-drev.pem 2>&1 | grep -q ': OK$' \
	|| fail "s-drev revoked by the base CRL"
openssl verify -no-CApath -CAfile rs.pem -crl_check -use_deltas -CRLfile crl/S-base.pem -CRLfile crl/S-delta.pem leaf/s-drev.pem 2>&1 \
	| grep -q 'certificate revoked' || fail "delta CRL does not revoke s-drev"
openssl verify -no-CApath -CAfile rs.pem -crl_check -CRLfile crl/S-notyet.pem leaf/s-ok.pem 2>&1 | grep -q 'error 11 ' || fail "S-notyet is not error 11"
rm -f u.pem rs.pem .last.log
chmod -R a+rX "$P"
echo "pki: OK ($(ls leaf/*.pem | wc -l) leaf certs, $(ls crl | wc -l) CRLs)"
