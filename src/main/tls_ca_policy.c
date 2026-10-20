/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file tls_ca_policy.c
 * @brief Per-CA revocation policy for "check_crl".
 *
 * With "check_crl = yes" OpenSSL wants a CRL from the issuer of every
 * client certificate.  "ca_policy" lines name the CAs which do have a
 * CRL, by the SHA-256 of the raw SubjectPublicKeyInfo of the CA
 * certificate.  If any certificate in the verified chain is named, CRL
 * errors stay as they are.  If none is, a fixed set of "no usable CRL"
 * errors is cleared, and every other check (signatures, validity,
 * trust, purpose, and CERT_REVOKED itself) still applies.
 *
 * The policy is parsed once, with the rest of the tls-config section,
 * and lives as long as the configuration does.
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>

#ifdef WITH_TLS
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define LOG_PREFIX "tls"

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#  define X509_STORE_CTX_get0_chain(_ctx) X509_STORE_CTX_get_chain(_ctx)
#  define X509_STORE_CTX_get1_certs(_ctx, _nm) X509_STORE_get1_certs(_ctx, _nm)
#endif

/** Hash the SubjectPublicKeyInfo of a certificate exactly as it was encoded in it
 *
 * i2d_X509_PUBKEY() encodes the X509_PUBKEY fields as they were parsed out of
 * the certificate (algorithm, parameters and the BIT STRING), not a key
 * re-derived from an EVP_PKEY.  For a DER certificate this gives back the
 * original bytes, so the hash does not depend on how a library would
 * re-encode the key (compressed EC points, RSA-PSS, RSA without NULL
 * parameters).  X509_pubkey_digest() is not used: it hashes the key bits only.
 */
static int ca_policy_spki_sha256(X509 *cert, uint8_t out[FR_TLS_CA_POLICY_KEY_LEN])
{
	unsigned char	*der = NULL;
	unsigned int	len = 0;
	int		der_len;
	int		rcode;

	der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
	if (der_len <= 0) return -1;

	rcode = EVP_Digest(der, der_len, out, &len, EVP_sha256(), NULL);
	OPENSSL_free(der);

	if (!rcode || (len != FR_TLS_CA_POLICY_KEY_LEN)) return -1;

	return 0;
}

/** Parse one "ca_policy" value: "<64 hex> <flag> [<flag>...]"
 *
 * Every error is fatal.  A token we do not know is an error and not a
 * warning, so that a configuration written for a newer binary fails the
 * "radiusd -C" check instead of being half applied.
 */
static int ca_policy_entry_parse(fr_tls_ca_policy_t *entry, char const *value)
{
	char const	*p = value;
	char const	*tok;
	size_t		len;

	memset(entry, 0, sizeof(*entry));

	while (isspace((uint8_t) *p)) p++;
	tok = p;
	while (*p && !isspace((uint8_t) *p)) p++;
	len = p - tok;

	if (!len) {
		fr_strerror_printf("missing the SHA-256 of the CA's SubjectPublicKeyInfo");
		return -1;
	}

	if (len != (FR_TLS_CA_POLICY_KEY_LEN * 2)) {
		fr_strerror_printf("key hash must be %d hex characters, got %zu",
				   FR_TLS_CA_POLICY_KEY_LEN * 2, len);
		return -1;
	}

	if (fr_hex2bin(entry->spki, sizeof(entry->spki), tok, len) != sizeof(entry->spki)) {
		fr_strerror_printf("key hash is not hex");
		return -1;
	}

	for (;;) {
		char const *eq;

		while (isspace((uint8_t) *p)) p++;
		if (!*p) break;

		tok = p;
		while (*p && !isspace((uint8_t) *p)) p++;
		len = p - tok;

		eq = memchr(tok, '=', len);

		if (((eq ? (size_t) (eq - tok) : len) == 3) && (strncmp(tok, "crl", 3) == 0)) {
			if (eq) {
				fr_strerror_printf("flag 'crl' takes no value");
				return -1;
			}
			if (entry->flags & FR_TLS_CA_POLICY_CRL) {
				fr_strerror_printf("flag 'crl' given twice");
				return -1;
			}
			entry->flags |= FR_TLS_CA_POLICY_CRL;
			continue;
		}

		fr_strerror_printf("unknown flag '%.*s'", (int) len, tok);
		return -1;
	}

	if (!entry->flags) {
		fr_strerror_printf("no flags after the key hash (expected 'crl')");
		return -1;
	}

	return 0;
}

/*
 *	X509_STORE_CTX ex_data: set when a CRL error was cleared during this
 *	verification, so that the warning is logged only once the chain has
 *	verified (see tls_ca_policy_verified()).
 */
static int ca_policy_ex_index = -1;

static fr_tls_ca_policy_t const *ca_policy_find(fr_tls_server_conf_t const *conf, uint8_t const *spki, uint32_t flag)
{
	uint32_t i;

	for (i = 0; i < conf->ca_policy_num; i++) {
		if ((conf->ca_policy_entries[i].flags & flag) &&
		    (memcmp(conf->ca_policy_entries[i].spki, spki, FR_TLS_CA_POLICY_KEY_LEN) == 0)) {
			return &conf->ca_policy_entries[i];
		}
	}

	return NULL;
}

/** Parse every "ca_policy" pair of a server tls-config section
 *
 * The table entry in tls_server_config[] only marks the pairs as parsed
 * (PW_TYPE_MULTI stores the first value alone), so walk them here.
 *
 * Always prints "tls: ca_policy: <N> entries in <section>", also for N == 0,
 * for every server TLS configuration parsed: an EAP tls-config, and also a
 * "tls" subsection of a listen or a client section.  <section> is the name
 * of the section, e.g. "tls-config tls-nac".  The line is at INFO level, so
 * it shows in "radiusd -XC" and in production logs alike: it is how a
 * consumer tells a binary which understands "ca_policy" from one which
 * silently ignores it (an unknown pair is only reported at debug level 3).
 * Do not change its wording without the consumers.
 *
 * @return 0 on success, -1 on a malformed or duplicate line.
 */
int tls_ca_policy_parse(fr_tls_server_conf_t *conf, CONF_SECTION *cs)
{
	CONF_PAIR	*cp;
	uint32_t	n = 0, i = 0, j;
	char const	*name2;

	for (cp = cf_pair_find(cs, "ca_policy"); cp; cp = cf_pair_find_next(cs, cp, "ca_policy")) n++;

	if (n) {
		conf->ca_policy_entries = talloc_zero_array(conf, fr_tls_ca_policy_t, n);
		if (!conf->ca_policy_entries) {
			ERROR(LOG_PREFIX ": Out of memory");
			return -1;
		}

		/*
		 *	Configuration is parsed before the worker threads
		 *	exist, so a plain check is enough here.
		 */
		if (ca_policy_ex_index < 0) {
			ca_policy_ex_index = X509_STORE_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
			if (ca_policy_ex_index < 0) {
				ERROR(LOG_PREFIX ": Failed allocating ex_data index for ca_policy");
				return -1;
			}
		}
	}

	for (cp = cf_pair_find(cs, "ca_policy"); cp; cp = cf_pair_find_next(cs, cp, "ca_policy")) {
		char const *value = cf_pair_value(cp);

		if (!value) {
			cf_log_err_cp(cp, LOG_PREFIX ": ca_policy \"\": missing value");
			return -1;
		}

		if (ca_policy_entry_parse(&conf->ca_policy_entries[i], value) < 0) {
			cf_log_err_cp(cp, LOG_PREFIX ": ca_policy \"%s\": %s", value, fr_strerror());
			return -1;
		}

		for (j = 0; j < i; j++) {
			if (memcmp(conf->ca_policy_entries[j].spki, conf->ca_policy_entries[i].spki,
				   FR_TLS_CA_POLICY_KEY_LEN) == 0) {
				cf_log_err_cp(cp, LOG_PREFIX ": ca_policy \"%s\": key hash already listed", value);
				return -1;
			}
		}
		i++;
	}
	conf->ca_policy_num = n;

	name2 = cf_section_name2(cs);
	INFO(LOG_PREFIX ": ca_policy: %u entries in %s%s%s", n, cf_section_name1(cs), name2 ? " " : "", name2 ? name2 : "");

	if (n && !conf->check_crl) {
		WARN(LOG_PREFIX ": ca_policy has no effect without check_crl = yes");
	}

	return 0;
}

/** OpenSSL errors which only say "there is no usable CRL for this certificate"
 *
 * CERT_REVOKED is never in the list: when OpenSSL found a CRL, verified it
 * with the issuer's key and the certificate is in it, that is proof of
 * revocation whatever the policy says.  Neither are errors which could also
 * come from something other than a CRL.
 */
static bool ca_policy_error_clearable(int err)
{
	switch (err) {
	case X509_V_ERR_UNABLE_TO_GET_CRL:
	case X509_V_ERR_CRL_SIGNATURE_FAILURE:
	case X509_V_ERR_CRL_NOT_YET_VALID:
	case X509_V_ERR_CRL_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
#ifdef X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER
	case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
#endif
#ifdef X509_V_ERR_KEYUSAGE_NO_CRL_SIGN
	case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
#endif
#ifdef X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION
	case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
#endif
#ifdef X509_V_ERR_DIFFERENT_CRL_SCOPE
	case X509_V_ERR_DIFFERENT_CRL_SCOPE:
#endif
#ifdef X509_V_ERR_CRL_PATH_VALIDATION_ERROR
	case X509_V_ERR_CRL_PATH_VALIDATION_ERROR:
#endif
		return true;

	default:
		return false;
	}
}

/** Remember an issuer key as logged, return true if it was already
 *
 * At most FR_TLS_CA_POLICY_LOGGED_MAX keys are remembered per store
 * generation.  Past that we log every time: noisy is better than silent.
 */
static bool ca_policy_logged(fr_tls_server_conf_t *conf, uint8_t const *spki)
{
	uint32_t	i;
	bool		seen = false;

	pthread_mutex_lock(&conf->mutex);
	for (i = 0; i < conf->ca_policy_logged_num; i++) {
		if (memcmp(conf->ca_policy_logged[i], spki, FR_TLS_CA_POLICY_KEY_LEN) == 0) {
			seen = true;
			break;
		}
	}
	if (!seen && (conf->ca_policy_logged_num < FR_TLS_CA_POLICY_LOGGED_MAX)) {
		memcpy(conf->ca_policy_logged[conf->ca_policy_logged_num++], spki, FR_TLS_CA_POLICY_KEY_LEN);
	}
	pthread_mutex_unlock(&conf->mutex);

	return seen;
}

/** Forget which issuers were logged.  Called with conf->mutex held, when the store is re-created
 *
 */
void tls_ca_policy_store_reset(fr_tls_server_conf_t *conf)
{
	conf->ca_policy_logged_num = 0;
}

/** Hash a certificate's key and look it up
 *
 * @return 1 listed with the flag, 0 not listed, -1 the key cannot be hashed.
 */
static int ca_policy_cert_listed(REQUEST *request, fr_tls_server_conf_t const *conf, X509 *cert, int depth,
				 uint32_t flag)
{
	uint8_t	spki[FR_TLS_CA_POLICY_KEY_LEN];
	char	hex[(FR_TLS_CA_POLICY_KEY_LEN * 2) + 1];

	if (!cert || (ca_policy_spki_sha256(cert, spki) < 0)) {
		RDEBUG2("(TLS) %s - ca_policy: cannot hash the key of certificate %d in chain", conf->name, depth);
		return -1;
	}

	if (!ca_policy_find(conf, spki, flag)) return 0;

	fr_bin2hex(hex, spki, sizeof(spki));
	RDEBUG2("(TLS) %s - ca_policy: certificate %d in chain (key sha256:%s) is listed", conf->name, depth, hex);

	return 1;
}

/** Look at every CA in the trust store which may have issued a certificate
 *
 * Several CA certificates can have the issuer's DN, e.g. a root re-issued
 * with a new key under the same name.  Without an AKID in the certificate,
 * nothing tells them apart short of checking the signature, so every
 * candidate which X509_check_issued() accepts counts: OR over all of them.
 *
 * @return 1 one of them is listed with the flag, 0 none is, -1 error.
 */
static int ca_policy_issuers_listed(REQUEST *request, fr_tls_server_conf_t const *conf, X509_STORE_CTX *ctx,
				    X509 *cert, int depth, uint32_t flag)
{
	STACK_OF(X509)	*candidates;
	int		i, rcode = 0;

	candidates = X509_STORE_CTX_get1_certs(ctx, X509_get_issuer_name(cert));
	if (!candidates) return 0;

	for (i = 0; i < sk_X509_num(candidates); i++) {
		X509 *candidate = sk_X509_value(candidates, i);

		if (X509_check_issued(candidate, cert) != X509_V_OK) continue;

		rcode = ca_policy_cert_listed(request, conf, candidate, depth, flag);
		if (rcode != 0) break;
	}
	sk_X509_pop_free(candidates, X509_free);

	return rcode;
}

/*
 *	How far above the verified chain we look for CAs.  It also ends
 *	loops of cross-certificates (A issued by B, B issued by A).
 */
#define CA_POLICY_MAX_WALK (16)

/** Is any certificate in the chain, up to its root, listed with a flag
 *
 * The chain is the verified one, leaf included (so that a chain of one has
 * an answer).  The key of a certificate's real issuer is always in it at
 * depth 1, whichever path (original, re-issued or cross-signed CA
 * certificate) OpenSSL built, because the leaf signature is verified with it.
 *
 * FreeRADIUS sets X509_V_FLAG_PARTIAL_CHAIN, so OpenSSL ends the verified
 * chain at the first certificate it finds in the trust store.  With the
 * intermediate CAs in ca_file that is usually the issuing CA itself, and
 * the CAs above it are not in X509_STORE_CTX_get0_chain().  So we carry on
 * from the top of the chain through the trust store: at each level every
 * candidate issuer counts (see ca_policy_issuers_listed()), and the walk
 * goes on through the one X509_STORE_CTX_get1_issuer() picks (DN, AKID
 * against SKID, key usage, validity; no signature check), until a
 * self-issued certificate, a certificate without an issuer in the store,
 * or CA_POLICY_MAX_WALK levels.  This only ever adds certificates, so it
 * can only find more listed CAs, never fewer.  Above depth 1 the result
 * depends on the path, as it does in OpenSSL's own chain.
 *
 * Any failure to hash a certificate or to look up an issuer is returned as
 * an error: callers must treat it as "listed" (fail closed).
 *
 * Not CRL specific: the OCSP per-CA flags are meant to use it too.
 *
 * @return 1 listed, 0 not listed, -1 error.
 */
int tls_ca_policy_chain_has(REQUEST *request, fr_tls_server_conf_t const *conf, X509_STORE_CTX *ctx, uint32_t flag)
{
	STACK_OF(X509)	*chain;
	X509		*top, *owned = NULL;
	int		i, num, rcode = 0;

	chain = X509_STORE_CTX_get0_chain(ctx);
	if (!chain) return -1;

	num = sk_X509_num(chain);
	if (num <= 0) return -1;

	for (i = 0; i < num; i++) {
		rcode = ca_policy_cert_listed(request, conf, sk_X509_value(chain, i), i, flag);
		if (rcode != 0) return rcode;
	}

	/*
	 *	Above the verified chain, through the trust store.  The
	 *	lookups may leave errors on the OpenSSL error queue, which
	 *	must not be mistaken for errors of the handshake.
	 */
	ERR_set_mark();
	top = sk_X509_value(chain, num - 1);
	for (i = num; i < (num + CA_POLICY_MAX_WALK); i++) {
		X509	*up = NULL;
		int	found;

		if (X509_check_issued(top, top) == X509_V_OK) break;	/* self-issued: a root */

		rcode = ca_policy_issuers_listed(request, conf, ctx, top, i, flag);
		if (rcode != 0) break;

		found = X509_STORE_CTX_get1_issuer(&up, ctx, top);
		if (found == 0) break;					/* not in the trust store */
		if ((found < 0) || !up) {
			RDEBUG2("(TLS) %s - ca_policy: error looking up the issuer of certificate %d in chain",
				conf->name, i - 1);
			rcode = -1;
			break;
		}

		if (X509_cmp(up, top) == 0) {				/* its own issuer, but not self-issued */
			X509_free(up);
			break;
		}

		X509_free(owned);
		owned = top = up;
	}
	X509_free(owned);
	ERR_pop_to_mark();

	return rcode;
}

/** Decide whether a CRL error for this chain is cleared by the policy
 *
 * If any certificate in the chain up to its root is listed with "crl", the
 * error stands.  Otherwise a "no usable CRL" error is cleared.  Adding a
 * line can therefore only make checking stricter.  An error while looking
 * keeps the error: fail closed.
 *
 * Nothing is logged at WARN level here: the chain has not been verified yet
 * (signatures come after the CRL check), so whatever it says is the
 * client's.  The clearing is remembered in the X509_STORE_CTX and logged by
 * tls_ca_policy_verified() once the chain has verified.
 *
 * @return true if the caller should clear the error and carry on.
 */
bool tls_ca_policy_clears(REQUEST *request, fr_tls_server_conf_t *conf, X509_STORE_CTX *ctx, int err)
{
	if (!ca_policy_error_clearable(err)) return false;

	if (tls_ca_policy_chain_has(request, conf, ctx, FR_TLS_CA_POLICY_CRL) != 0) {
		RDEBUG2("(TLS) %s - ca_policy: CRL check stays", conf->name);
		return false;
	}

	RDEBUG2("(TLS) %s - ca_policy: no CA in the chain has a CRL configured, clearing OpenSSL error %d : %s",
		conf->name, err, X509_verify_cert_error_string(err));

	if (ca_policy_ex_index >= 0) X509_STORE_CTX_set_ex_data(ctx, ca_policy_ex_index, &ca_policy_ex_index);

	return true;
}

/** Log a cleared CRL check, once the chain has verified
 *
 * Called for depth 0 with ok = 1, i.e. after OpenSSL verified the
 * signatures of the whole chain.  Logs once per issuer key per X509 store.
 * A chain of one (a client certificate trusted directly) is logged with
 * the certificate's own key, as it has no issuer in the chain.
 */
void tls_ca_policy_verified(REQUEST *request, fr_tls_server_conf_t *conf, X509_STORE_CTX *ctx)
{
	STACK_OF(X509)	*chain;
	X509		*leaf, *key_cert;
	int		num;
	uint8_t		spki[FR_TLS_CA_POLICY_KEY_LEN];
	char		subject[1024], issuer[1024];
	char		hex[(FR_TLS_CA_POLICY_KEY_LEN * 2) + 1];

	if ((ca_policy_ex_index < 0) || !X509_STORE_CTX_get_ex_data(ctx, ca_policy_ex_index)) return;
	X509_STORE_CTX_set_ex_data(ctx, ca_policy_ex_index, NULL);

	chain = X509_STORE_CTX_get0_chain(ctx);
	if (!chain || ((num = sk_X509_num(chain)) <= 0)) return;

	leaf = sk_X509_value(chain, 0);
	key_cert = (num > 1) ? sk_X509_value(chain, 1) : leaf;

	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(leaf), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	if (ca_policy_spki_sha256(key_cert, spki) < 0) {
		WARN("(TLS) %s: CRL not checked for '%s': no CA in its chain has a CRL configured", conf->name, subject);
		return;
	}
	if (ca_policy_logged(conf, spki)) return;

	fr_bin2hex(hex, spki, sizeof(spki));
	if (num == 1) {
		WARN("(TLS) %s: CRL not checked for '%s': no CA in its chain has a CRL configured "
		     "(certificate trusted directly, its own key sha256:%s)", conf->name, subject, hex);
		return;
	}

	X509_NAME_oneline(X509_get_subject_name(key_cert), issuer, sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';
	WARN("(TLS) %s: CRL not checked for '%s': no CA in its chain has a CRL configured "
	     "(issuer '%s', issuer key sha256:%s)", conf->name, subject, issuer, hex);

	RDEBUG2("(TLS) %s - ca_policy: CRL check was cleared for this chain", conf->name);
}
#endif	/* WITH_TLS */
