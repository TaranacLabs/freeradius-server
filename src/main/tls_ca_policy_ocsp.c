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
 * @file tls_ca_policy_ocsp.c
 * @brief Per-CA OCSP: the "ocsp" and "ocsp_url=" flags of "ca_policy".
 *
 * A client certificate is checked with OCSP if any CA in its verified
 * chain, up to the root, has a "ca_policy" line with the flag "ocsp" (the
 * same OR as for "crl").  The responder is the "ocsp_url" of the nearest
 * such CA if it has one, else the first http OCSP entry in the AIA of the
 * client certificate.  Only the client certificate is checked, once, after
 * OpenSSL has checked the signatures, times and CRLs of its chain.  If the
 * check cannot be made, the client is rejected: there is no soft fail.
 *
 * This is not the "ocsp { }" section, which applies to every client
 * certificate, and the two cannot be used together.  The differences:
 *
 *  - no nonce, ever.  Microsoft's Online Responder answers "unauthorized"
 *    to a request with one.  Freshness comes from thisUpdate / nextUpdate,
 *    and a response without nextUpdate must be at most
 *    OCSP_MAX_AGE seconds old.
 *  - one deadline, FR_TLS_CA_POLICY_OCSP_TIMEOUT, for the whole exchange:
 *    waiting for a slot, connecting, sending and reading.  OpenSSL counts
 *    in whole seconds of time(), and polls past the deadline by up to a
 *    second after a refused connection or a failed name lookup.  Name
 *    resolution itself is not bounded by OpenSSL.
 *  - at most FR_TLS_CA_POLICY_OCSP_INFLIGHT requests at a time per
 *    tls-config, and at most FR_TLS_CA_POLICY_OCSP_WAITERS more waiting for
 *    a slot, each for at most FR_TLS_CA_POLICY_OCSP_SLOT_WAIT out of the
 *    same deadline.  Beyond that a check fails at once ("busy").  So a slow
 *    or dead responder holds at most INFLIGHT + WAITERS worker threads.  The
 *    slots are per tls-config, not per responder: a dead responder of one
 *    CA can make checks for another CA fail as "busy".
 *  - the signer of the response is verified against a store without CRL
 *    flags, with the client's verified chain as the untrusted
 *    certificates.  So a response signed by the CA itself verifies without
 *    a certificate in it, and a CA without a CRL does not break it.
 *  - every outcome other than "good" leaves one line, the verdict, in
 *    Module-Failure-Message.  See tls_ca_policy_ocsp().
 *
 * There is no cache of responses: one request per full handshake.
 *
 * Written against, and tested with, OpenSSL 3.3: the OSSL_HTTP_* timeout
 * semantics relied on here were read in that version.
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/radiusd.h>

#if defined(WITH_TLS) && defined(WITH_TLS_CA_POLICY_OCSP)
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/err.h>
#include <openssl/http.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#define LOG_PREFIX "tls"

/*
 *	Clock skew allowed on thisUpdate / nextUpdate, and the largest age
 *	of a response without nextUpdate.  Both in seconds.
 */
#define OCSP_MAX_SKEW	(5 * 60)
#define OCSP_MAX_AGE	(5 * 60)

/*
 *	The slot wait runs on the monotonic clock where the condition
 *	variable can be told to, so that a step of the wall clock does not
 *	stretch it.  OpenSSL's own deadlines are on time() regardless.
 */
#if defined(CLOCK_MONOTONIC) && !defined(__APPLE__)
#  define OCSP_SLOT_CLOCK CLOCK_MONOTONIC
#endif

/** Requests in flight and waiting, per tls-config
 *
 * The counters are used with conf->mutex held.  A talloc child of the
 * configuration, so that it goes with it.
 */
struct fr_tls_ca_policy_ocsp_slots_t {
	pthread_cond_t	cond;		//!< Signalled when a slot is given back.
	uint32_t	inflight;
	uint32_t	waiting;
};

/** What one check came to, and the words for it
 *
 */
typedef struct {
	fr_tls_ca_policy_ocsp_t	result;
	char const		*verdict;	//!< "revoked", "unknown", "failed <class>".
	int			x509_err;	//!< Set in the X509_STORE_CTX on a reject.
	unsigned long		err_before;	//!< Last OpenSSL error before the check.
	char			detail[512];
} ocsp_outcome_t;

typedef enum {
	OCSP_SLOT_TAKEN = 0,			//!< Give it back with ocsp_slot_give().
	OCSP_SLOT_FULL,				//!< INFLIGHT in flight and WAITERS waiting.
	OCSP_SLOT_TIMEOUT,			//!< Waited SLOT_WAIT, no slot came free.
	OCSP_SLOT_ERROR				//!< The wait itself failed.
} ocsp_slot_t;

static int _ocsp_slots_free(fr_tls_ca_policy_ocsp_slots_t *slots)
{
	pthread_cond_destroy(&slots->cond);
	return 0;
}

/** The last OpenSSL error raised since the innermost mark, 0 if none
 *
 * Where ERR_count_to_mark() exists (3.2), it says whether there is one.
 * Before that, a new error is told from an old one by its code only.
 */
static unsigned long ocsp_new_error(unsigned long before, char const **data, int *flags)
{
	char const	*file = NULL, *func = NULL;
	int		line = 0;
	unsigned long	code;

	*data = NULL;
	*flags = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30200000L
	(void) before;
	if (ERR_count_to_mark() == 0) return 0;
	code = ERR_peek_last_error_all(&file, &line, &func, data, flags);
#else
	code = ERR_peek_last_error_all(&file, &line, &func, data, flags);
	if (code == before) return 0;
#endif

	return code;
}

/** Create the OCSP signer store and the slots of a tls-config
 *
 * The store has the trusted CAs (ca_file, ca_path) and PARTIAL_CHAIN, and no
 * CRL flags: the chain of the signer of a response is not checked for
 * revocation, as the CAs of the client chain are not checked with OCSP.  A
 * CRL flag would also need the CRL of the root for every response signed
 * by a sub-CA, and fail for CAs without one.  OpenSSL 3 skips the CRL check
 * of a delegated signer with id-pkix-ocsp-nocheck anyway.
 *
 * The store is created once, here: ca_path_reload_interval does not
 * re-create it (ca_path is still looked up by hash when needed).  It goes in
 * conf->ocsp_store, which is free as "ocsp { enable }" and "ca_policy ...
 * ocsp" cannot be used together, and is freed with the configuration.
 *
 * Called after the mutex is initialised.
 *
 * @return 0 on success, -1 on error.
 */
int tls_ca_policy_ocsp_init(fr_tls_server_conf_t *conf)
{
	fr_tls_ca_policy_ocsp_slots_t	*slots;
	X509_STORE			*store;
	pthread_condattr_t		attr;
	int				rcode;

	slots = talloc_zero(conf, fr_tls_ca_policy_ocsp_slots_t);
	if (!slots) {
		ERROR(LOG_PREFIX ": Out of memory");
		return -1;
	}

	rcode = pthread_condattr_init(&attr);
	if (rcode == 0) {
#ifdef OCSP_SLOT_CLOCK
		rcode = pthread_condattr_setclock(&attr, OCSP_SLOT_CLOCK);
#endif
		if (rcode == 0) rcode = pthread_cond_init(&slots->cond, &attr);
		pthread_condattr_destroy(&attr);
	}
	if (rcode != 0) {
		ERROR(LOG_PREFIX ": Failed initialising the OCSP slots of ca_policy: %s", fr_syserror(rcode));
		talloc_free(slots);
		return -1;
	}
	talloc_set_destructor(slots, _ocsp_slots_free);

	store = X509_STORE_new();
	if (!store) {
		ERROR(LOG_PREFIX ": Out of memory");
		talloc_free(slots);
		return -1;
	}

	if ((conf->ca_file || conf->ca_path) && !X509_STORE_load_locations(store, conf->ca_file, conf->ca_path)) {
		tls_error_log(NULL, "Error reading Trusted root CA list \"%s\" for ca_policy OCSP", conf->ca_file);
		X509_STORE_free(store);
		talloc_free(slots);
		return -1;
	}
	X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);

	conf->ocsp_store = store;
	conf->ca_policy_ocsp_slots = slots;

	return 0;
}

/** Is an explicit port of 0 given in a URL
 *
 * OSSL_HTTP_parse_url() turns ":0" into the default port, so look for it.
 */
static bool ocsp_url_port_zero(char const *url)
{
	char const	*a, *end, *p;
	bool		digits = false;

	a = strstr(url, "://");
	a = a ? a + 3 : url;
	end = a + strcspn(a, "/?#");

	p = memchr(a, '@', end - a);
	if (p) a = p + 1;

	if (*a == '[') {
		p = memchr(a, ']', end - a);
		if (!p) return false;
		p++;
	} else {
		p = a + strcspn(a, ":/?#");
	}
	if ((p >= end) || (*p != ':')) return false;

	for (p++; p < end; p++) {
		if (*p != '0') return false;
		digits = true;
	}

	return digits;
}

/** Split an OCSP responder URL into host, port and path
 *
 * Only http: responses are signed, TLS adds nothing to them.  The scheme is
 * case-insensitive.  The port defaults to 80 and the path to "/"; a query
 * stays in the path.  Only printable ASCII without spaces (0x21 - 0x7e) is
 * accepted: the URL goes into the HTTP request line and into the verdict.
 *
 * @param[in] ctx	talloc parent of the strings.
 * @param[in] url	to parse.
 * @param[out] host	of the responder.
 * @param[out] port	of the responder.
 * @param[out] path	to POST to.
 * @return 0 on success, -1 with fr_strerror() on error.
 */
int tls_ca_policy_ocsp_url_parse(TALLOC_CTX *ctx, char const *url, char const **host, char const **port,
				 char const **path)
{
	static char const https[] = "https responder URLs are not supported: OCSP responses are signed, use http";
	char		*copy, *h = NULL, *p = NULL, *u = NULL;
	char const	*c, *data;
	int		ssl = 0, i, rcode = -1, flags;
	unsigned long	before, code;

	for (c = url; *c; c++) {
		if ((*c < 0x21) || (*c > 0x7e)) {
			fr_strerror_printf("the responder URL has a byte outside printable ASCII (0x%02x)",
					   (unsigned int) (uint8_t) *c);
			return -1;
		}
	}

	if (strncasecmp(url, "https://", 8) == 0) {
		fr_strerror_printf("%s", https);
		return -1;
	}

	if (strncasecmp(url, "http://", 7) != 0) {
		fr_strerror_printf("the responder URL must start with http://");
		return -1;
	}

	if (ocsp_url_port_zero(url)) {
		fr_strerror_printf("the responder URL has port 0");
		return -1;
	}

	/*
	 *	OpenSSL compares the scheme case-sensitively.
	 */
	copy = talloc_strdup(ctx, url);
	if (!copy) {
		fr_strerror_printf("out of memory");
		return -1;
	}
	for (i = 0; i < 4; i++) copy[i] = tolower((uint8_t) copy[i]);

	before = ERR_peek_last_error();
	ERR_set_mark();
	if (!OSSL_HTTP_parse_url(copy, &ssl, NULL, &h, &p, NULL, &u, NULL, NULL)) {
		char const *reason = NULL;

		code = ocsp_new_error(before, &data, &flags);
		if (code) reason = ERR_reason_error_string(code);
		fr_strerror_printf("cannot parse the responder URL%s%s", reason ? ": " : "", reason ? reason : "");
		goto done;
	}
	if (ssl) {
		fr_strerror_printf("%s", https);
		goto done;
	}
	if (!h || !*h || !p || !*p || !u || !*u) {
		fr_strerror_printf("the responder URL needs a host, a port and a path");
		goto done;
	}

	*host = talloc_strdup(ctx, h);
	*port = talloc_strdup(ctx, p);
	*path = talloc_strdup(ctx, u);
	if (!*host || !*port || !*path) {
		fr_strerror_printf("out of memory");
		goto done;
	}
	rcode = 0;

done:
	ERR_pop_to_mark();
	talloc_free(copy);
	OPENSSL_free(h);
	OPENSSL_free(p);
	OPENSSL_free(u);

	return rcode;
}

/** Take a slot for a request
 *
 * With INFLIGHT requests in flight, wait for one to finish, at most
 * SLOT_WAIT, unless WAITERS are waiting already: then fail at once.
 *
 * conf->mutex is taken without a timeout.  It is only ever held for
 * moments (the slots, the table of logged issuers, and the re-creation of
 * the X509 store by ca_path_reload_interval), and never across the network.
 *
 * @param[in] conf	of the tls-config.
 * @param[out] err	the error of the wait, for OCSP_SLOT_ERROR.
 * @return one of ocsp_slot_t.
 */
static ocsp_slot_t ocsp_slot_take(fr_tls_server_conf_t *conf, int *err)
{
	fr_tls_ca_policy_ocsp_slots_t	*slots = conf->ca_policy_ocsp_slots;
	struct timespec			until;
	ocsp_slot_t			rcode = OCSP_SLOT_TAKEN;
	int				ret = 0;

	*err = 0;

#ifdef OCSP_SLOT_CLOCK
	clock_gettime(OCSP_SLOT_CLOCK, &until);
#else
	{
		struct timeval now;

		gettimeofday(&now, NULL);
		until.tv_sec = now.tv_sec;
		until.tv_nsec = now.tv_usec * 1000;
	}
#endif
	until.tv_sec += FR_TLS_CA_POLICY_OCSP_SLOT_WAIT;

	pthread_mutex_lock(&conf->mutex);
	if (slots->inflight >= FR_TLS_CA_POLICY_OCSP_INFLIGHT) {
		if (slots->waiting >= FR_TLS_CA_POLICY_OCSP_WAITERS) {
			rcode = OCSP_SLOT_FULL;
			goto done;
		}

		slots->waiting++;
		while (slots->inflight >= FR_TLS_CA_POLICY_OCSP_INFLIGHT) {
			ret = pthread_cond_timedwait(&slots->cond, &conf->mutex, &until);
			if (ret != 0) break;
		}
		slots->waiting--;

		if (slots->inflight >= FR_TLS_CA_POLICY_OCSP_INFLIGHT) {
			if (ret == ETIMEDOUT) {
				rcode = OCSP_SLOT_TIMEOUT;
			} else {
				*err = ret;
				rcode = OCSP_SLOT_ERROR;
			}
			goto done;
		}
	}
	slots->inflight++;

done:
	pthread_mutex_unlock(&conf->mutex);

	return rcode;
}

static void ocsp_slot_give(fr_tls_server_conf_t *conf)
{
	fr_tls_ca_policy_ocsp_slots_t *slots = conf->ca_policy_ocsp_slots;

	pthread_mutex_lock(&conf->mutex);
	slots->inflight--;
	pthread_cond_signal(&slots->cond);
	pthread_mutex_unlock(&conf->mutex);
}

/** Record a reject
 *
 * For a failure the responder or OpenSSL is behind ("failed transport",
 * "failed response", "failed verify"), the OpenSSL error raised in the
 * check, if there is one, is added: the last one on the queue, with its
 * data (where OCSP_basic_verify() puts the reason, and the HTTP client the
 * server).  The detail of "revoked", "unknown", "busy" and "config" is ours
 * alone.
 */
static void ocsp_reject(ocsp_outcome_t *out, char const *verdict, int x509_err, bool openssl, char const *fmt, ...)
	CC_HINT(format (printf, 5, 6));
static void ocsp_reject(ocsp_outcome_t *out, char const *verdict, int x509_err, bool openssl, char const *fmt, ...)
{
	va_list		ap;
	size_t		len;
	unsigned long	code;
	char const	*data;
	int		flags;
	char		buf[256];

	out->result = FR_TLS_CA_POLICY_OCSP_FAILED;
	out->verdict = verdict;
	out->x509_err = x509_err;

	va_start(ap, fmt);
	vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
	va_end(ap);

	if (!openssl) return;

	code = ocsp_new_error(out->err_before, &data, &flags);
	if (!code) return;

	ERR_error_string_n(code, buf, sizeof(buf));
	len = strlen(out->detail);
	snprintf(out->detail + len, sizeof(out->detail) - len, " (%s%s%s)", buf,
		 ((flags & ERR_TXT_STRING) && data && *data) ? ": " : "",
		 ((flags & ERR_TXT_STRING) && data && *data) ? data : "");
}

/*
 *	The classes of "failed" (a contract, see tls_ca_policy_ocsp()).
 */
#define REJECT_TRANSPORT(_fmt, ...)	ocsp_reject(&out, "failed transport", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)
#define REJECT_BUSY(_fmt, ...)		ocsp_reject(&out, "failed busy", OCSP_X509_ERR_FAILED, false, _fmt, ## __VA_ARGS__)
#define REJECT_RESPONSE(_fmt, ...)	ocsp_reject(&out, "failed response", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)
#define REJECT_VERIFY(_fmt, ...)	ocsp_reject(&out, "failed verify", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)
#define REJECT_CONFIG(_fmt, ...)	ocsp_reject(&out, "failed config", OCSP_X509_ERR_FAILED, false, _fmt, ## __VA_ARGS__)

#ifdef X509_V_ERR_OCSP_VERIFY_FAILED
#  define OCSP_X509_ERR_FAILED	X509_V_ERR_OCSP_VERIFY_FAILED
#else
#  define OCSP_X509_ERR_FAILED	X509_V_ERR_CERT_REVOKED
#endif
#ifdef X509_V_ERR_OCSP_CERT_UNKNOWN
#  define OCSP_X509_ERR_UNKNOWN	X509_V_ERR_OCSP_CERT_UNKNOWN
#else
#  define OCSP_X509_ERR_UNKNOWN	X509_V_ERR_CERT_REVOKED
#endif

/** Format an OCSP time as ISO 8601, UTC
 *
 */
static char const *ocsp_time(char *buf, size_t len, ASN1_GENERALIZEDTIME const *t)
{
	struct tm tm;

	if (!t) return "none";
	if (!ASN1_TIME_to_tm(t, &tm) || !strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm)) return "unreadable";

	return buf;
}

/** Pick the responder from the AIA of a certificate: the first http OCSP entry
 *
 * https and ldap entries, and entries which do not parse or have bytes
 * outside printable ASCII, are skipped.
 *
 * @return 0 found, -1 none, -2 out of memory.
 */
static int ocsp_aia_url(REQUEST *request, TALLOC_CTX *ctx, X509 *leaf, char const **url,
			char const **host, char const **port, char const **path)
{
	STACK_OF(OPENSSL_STRING)	*uris;
	int				i, rcode = -1;

	uris = X509_get1_ocsp(leaf);
	if (!uris) return -1;

	for (i = 0; i < sk_OPENSSL_STRING_num(uris); i++) {
		char const *uri = sk_OPENSSL_STRING_value(uris, i);

		if (!uri) continue;

		if (tls_ca_policy_ocsp_url_parse(ctx, uri, host, port, path) < 0) {
			RDEBUG2("(TLS) ocsp: skipping an AIA OCSP entry: %s", fr_strerror());
			continue;
		}

		*url = talloc_strdup(ctx, uri);
		rcode = *url ? 0 : -2;
		break;
	}
	X509_email_free(uris);

	return rcode;
}

/** Check a client certificate with OCSP, if a CA in its chain says so
 *
 * Called for depth 0 with ok = 1: OpenSSL has checked the signatures, the
 * times and the CRLs of the chain (name constraints and RFC 3779 come
 * after).  On a reject, the X509_STORE_CTX error is set so that the client
 * gets an alert which says why (certificate_revoked for a revoked
 * certificate), and one line goes to Module-Failure-Message:
 *
 *	(TLS) ocsp verdict revoked: reason <reason>, revoked at <time>; responder <url>
 *	(TLS) ocsp verdict unknown: the responder does not know the certificate; responder <url>
 *	(TLS) ocsp verdict failed <class>: <detail>; responder <url or none>
 *
 * <class> is one of:
 *  - transport	no usable answer in time: name, connection, timeout,
 *		HTTP status other than 200, not a DER OCSP response.
 *  - busy	the slots of this tls-config are taken (FR_TLS_CA_POLICY_OCSP_
 *		INFLIGHT in flight and WAITERS waiting, or no slot within
 *		SLOT_WAIT).  Says nothing about this responder.
 *  - response	the responder answered with responseStatus other than
 *		successful (tryLater, unauthorized, ...), or not with a basic
 *		response.
 *  - verify	the response does not hold: signature or signer, no status
 *		for the certificate, times.
 *  - config	the check could not be made here: no responder URL, no
 *		issuer, the chain could not be looked at, out of memory, not
 *		initialised.
 *
 * "ocsp verdict", the three verdicts and the five classes are parsed by
 * consumers of the log, as is the "ca_policy: N entries" marker.  Do not
 * change them.
 *
 * TLS-OCSP-Cert-Valid is set to 1 (good), 0 (reject) or 2 (not needed).
 *
 * @return
 *	- FR_TLS_CA_POLICY_OCSP_GOOD the responder said "good".
 *	- FR_TLS_CA_POLICY_OCSP_NOT_NEEDED no CA in the chain has "ocsp".
 *	- FR_TLS_CA_POLICY_OCSP_FAILED reject the client.
 */
fr_tls_ca_policy_ocsp_t tls_ca_policy_ocsp(REQUEST *request, fr_tls_server_conf_t *conf, X509_STORE_CTX *ctx,
					   X509 *leaf)
{
	ocsp_outcome_t		out;
	fr_tls_ca_policy_t const *line = NULL;
	STACK_OF(X509)		*chain = NULL, *certs = NULL;
	X509			*issuer = NULL, *issuer_owned = NULL;
	OCSP_CERTID		*certid = NULL;
	OCSP_REQUEST		*req = NULL;
	OCSP_RESPONSE		*resp = NULL;
	OCSP_BASICRESP		*bresp = NULL;
	BIO			*req_bio = NULL, *resp_bio = NULL;
	OSSL_HTTP_REQ_CTX	*rctx = NULL;
	TALLOC_CTX		*tmp = NULL;
	char const		*url = NULL, *host = NULL, *port = NULL, *path = NULL;
	time_t			deadline;
	long			left;
	bool			slot = false;
	int			status = -1, reason = -1, rcode, err;
	ASN1_GENERALIZEDTIME	*rev = NULL, *thisupd = NULL, *nextupd = NULL;
	char			t1[32], t2[32];
	VALUE_PAIR		*vp;

	deadline = time(NULL) + FR_TLS_CA_POLICY_OCSP_TIMEOUT;

	/*
	 *	Whatever OpenSSL leaves on the error queue from here on
	 *	must not be mistaken for an error of the handshake.
	 */
	memset(&out, 0, sizeof(out));
	out.result = FR_TLS_CA_POLICY_OCSP_FAILED;
	out.err_before = ERR_peek_last_error();
	ERR_set_mark();

	switch (tls_ca_policy_chain_find(request, conf, ctx, FR_TLS_CA_POLICY_OCSP, &line)) {
	case 0:
		RDEBUG2("(TLS) %s - ca_policy: no CA in the chain has OCSP configured", conf->name);
		out.result = FR_TLS_CA_POLICY_OCSP_NOT_NEEDED;
		goto done;

	case 1:
		break;

	default:
		REJECT_CONFIG("cannot evaluate the chain");
		goto done;
	}

	if (!conf->ocsp_store || !conf->ca_policy_ocsp_slots) {
		REJECT_CONFIG("per-CA OCSP is not initialised");
		goto done;
	}

	/*
	 *	The CertID is about the issuer of the leaf, the
	 *	certificate at depth 1 of the verified chain.  A leaf
	 *	trusted directly (a chain of one) gets its issuer from
	 *	the trust store, as the walk up does.
	 */
	chain = X509_STORE_CTX_get0_chain(ctx);
	if (!chain || (sk_X509_num(chain) < 1)) {
		REJECT_CONFIG("cannot evaluate the chain");
		goto done;
	}
	if (sk_X509_num(chain) > 1) {
		issuer = sk_X509_value(chain, 1);
	} else if ((X509_STORE_CTX_get1_issuer(&issuer_owned, ctx, leaf) == 1) && issuer_owned &&
		   (X509_cmp(issuer_owned, leaf) != 0)) {
		issuer = issuer_owned;
		certs = sk_X509_dup(chain);
		if (!certs || !sk_X509_push(certs, issuer)) {
			REJECT_CONFIG("out of memory");
			goto done;
		}
	}
	if (!issuer) {
		REJECT_CONFIG("no issuer certificate");
		goto done;
	}

	tmp = talloc_new(request);
	if (!tmp) {
		REJECT_CONFIG("out of memory");
		goto done;
	}

	/*
	 *	The URL of the CA wins over the AIA of the leaf, always.
	 */
	if (line->ocsp_url) {
		url = line->ocsp_url;
		host = line->ocsp_host;
		port = line->ocsp_port;
		path = line->ocsp_path;
	} else {
		switch (ocsp_aia_url(request, tmp, leaf, &url, &host, &port, &path)) {
		case 0:
			break;

		case -2:
			url = NULL;
			REJECT_CONFIG("out of memory");
			goto done;

		default:
			url = NULL;
			REJECT_CONFIG("no OCSP responder URL (none configured for the CA, "
				      "no http OCSP entry in the certificate's AIA)");
			goto done;
		}
	}

	RDEBUG2("(TLS) %s - ca_policy: OCSP request to %s (%s)", conf->name, url,
		line->ocsp_url ? "configured for the CA" : "from the certificate's AIA");

	/*
	 *	SHA-1 CertID and no nonce (RFC 5019).
	 */
	req = OCSP_REQUEST_new();
	certid = OCSP_cert_to_id(NULL, leaf, issuer);
	if (!req || !certid) {
		OCSP_CERTID_free(certid);
		certid = NULL;
		REJECT_CONFIG("cannot build the OCSP request");
		goto done;
	}
	if (!OCSP_request_add0_id(req, certid)) {
		OCSP_CERTID_free(certid);
		certid = NULL;
		REJECT_CONFIG("cannot build the OCSP request");
		goto done;
	}
	/* certid now belongs to req, and lives as long as it does */

	req_bio = ASN1_item_i2d_mem_bio(ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE const *) req);
	if (!req_bio) {
		REJECT_CONFIG("cannot encode the OCSP request");
		goto done;
	}

	/*
	 *	Taken before the name is resolved, so that a hung
	 *	resolver holds no more than the slots.
	 */
	switch (ocsp_slot_take(conf, &err)) {
	case OCSP_SLOT_TAKEN:
		slot = true;
		break;

	case OCSP_SLOT_FULL:
		REJECT_BUSY("%d OCSP requests in progress and %d waiting for this tls-config",
			    FR_TLS_CA_POLICY_OCSP_INFLIGHT, FR_TLS_CA_POLICY_OCSP_WAITERS);
		goto done;

	case OCSP_SLOT_TIMEOUT:
		REJECT_BUSY("%d OCSP requests in progress for this tls-config, none finished within %d s",
			    FR_TLS_CA_POLICY_OCSP_INFLIGHT, FR_TLS_CA_POLICY_OCSP_SLOT_WAIT);
		goto done;

	case OCSP_SLOT_ERROR:
		REJECT_CONFIG("cannot wait for an OCSP slot: %s", fr_syserror(err));
		goto done;
	}

	/*
	 *	One deadline for everything.  OSSL_HTTP_transfer() would
	 *	give the connection the whole timeout and then start it
	 *	again for the exchange, so the steps are made one by one
	 *	with what is left.  The proxy is "", not NULL: NULL
	 *	reads http_proxy from the environment.  No Content-Type
	 *	is required of the answer (as OCSP_sendreq_new() does):
	 *	the DER and its signature are what is checked.
	 */
	left = (long) (deadline - time(NULL));
	if (left <= 0) {
		REJECT_BUSY("no time left for the OCSP request after waiting for a slot");
		goto done;
	}

	rctx = OSSL_HTTP_open(host, port, "", NULL, 0, NULL, NULL, NULL, NULL, 0, (int) left);
	if (!rctx) {
		REJECT_TRANSPORT("cannot connect to the responder");
		goto done;
	}

	left = (long) (deadline - time(NULL));
	if (left <= 0) {
		REJECT_TRANSPORT("timed out connecting to the responder");
		goto done;
	}

	if (!OSSL_HTTP_set1_request(rctx, path, NULL, "application/ocsp-request", req_bio,
				    NULL, 1, FR_TLS_CA_POLICY_OCSP_MAX_RESP, (int) left, 0)) {
		REJECT_CONFIG("cannot set up the HTTP request");
		goto done;
	}

	resp_bio = OSSL_HTTP_exchange(rctx, NULL);
	if (!resp_bio) {
		REJECT_TRANSPORT("no HTTP 200 answer from the responder");
		goto done;
	}

	OSSL_HTTP_close(rctx, 1);
	rctx = NULL;
	ocsp_slot_give(conf);
	slot = false;

	resp = d2i_OCSP_RESPONSE_bio(resp_bio, NULL);
	if (!resp) {
		REJECT_TRANSPORT("the answer is not a DER OCSP response");
		goto done;
	}

	rcode = OCSP_response_status(resp);
	if (rcode != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		REJECT_RESPONSE("the responder answered %s (%d)", OCSP_response_status_str(rcode), rcode);
		goto done;
	}

	bresp = OCSP_response_get1_basic(resp);
	if (!bresp) {
		REJECT_RESPONSE("not a basic OCSP response");
		goto done;
	}

	/*
	 *	The signer is looked for in the client's verified chain,
	 *	then in the response, and must be the issuer of the leaf
	 *	or a responder it delegated to (EKU OCSPSigning).
	 *
	 *	Flags must stay 0.  Never OCSP_TRUSTOTHER: it skips the
	 *	verification of a signer found in the chain, and the
	 *	client holds the key of its own certificate.  -1 (error)
	 *	is a failure as much as 0.
	 */
	if (OCSP_basic_verify(bresp, certs ? certs : chain, conf->ocsp_store, 0) <= 0) {
		REJECT_VERIFY("the response signature or signer does not verify");
		goto done;
	}

	if (!OCSP_resp_find_status(bresp, certid, &status, &reason, &rev, &thisupd, &nextupd)) {
		REJECT_VERIFY("the response has no status for the certificate");
		goto done;
	}

	/*
	 *	Without nextUpdate, a response must be recent: no nonce
	 *	says it was made for this request.
	 */
	if (!OCSP_check_validity(thisupd, nextupd, OCSP_MAX_SKEW, nextupd ? -1 : OCSP_MAX_AGE)) {
		REJECT_VERIFY("the response is not current (thisUpdate %s, nextUpdate %s)",
			      ocsp_time(t1, sizeof(t1), thisupd), ocsp_time(t2, sizeof(t2), nextupd));
		goto done;
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		out.result = FR_TLS_CA_POLICY_OCSP_GOOD;
		break;

	case V_OCSP_CERTSTATUS_REVOKED:
		ocsp_reject(&out, "revoked", X509_V_ERR_CERT_REVOKED, false, "reason %s, revoked at %s",
			    (reason >= 0) ? OCSP_crl_reason_str(reason) : "not given",
			    ocsp_time(t1, sizeof(t1), rev));
		break;

	case V_OCSP_CERTSTATUS_UNKNOWN:
		ocsp_reject(&out, "unknown", OCSP_X509_ERR_UNKNOWN, false, "the responder does not know the certificate");
		break;

	default:
		REJECT_VERIFY("unexpected certificate status %d", status);
		break;
	}

done:
	if (rctx) OSSL_HTTP_close(rctx, 0);
	if (slot) ocsp_slot_give(conf);

	BIO_free(req_bio);
	BIO_free(resp_bio);
	OCSP_REQUEST_free(req);		/* and certid */
	OCSP_RESPONSE_free(resp);
	OCSP_BASICRESP_free(bresp);
	sk_X509_free(certs);
	X509_free(issuer_owned);

	vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
	switch (out.result) {
	case FR_TLS_CA_POLICY_OCSP_GOOD:
		if (vp) vp->vp_integer = 1;	/* yes */
		RDEBUG2("(TLS) ocsp verdict good; responder %s", url);
		break;

	case FR_TLS_CA_POLICY_OCSP_NOT_NEEDED:
		if (vp) vp->vp_integer = 2;	/* not checked */
		break;

	case FR_TLS_CA_POLICY_OCSP_FAILED:
		if (vp) vp->vp_integer = 0;	/* no */
		if (!out.verdict) out.verdict = "failed config";	/* not reached */
		X509_STORE_CTX_set_error(ctx, out.x509_err ? out.x509_err : OCSP_X509_ERR_FAILED);
		RERROR("(TLS) ocsp verdict %s: %s; responder %s", out.verdict, out.detail, url ? url : "none");
		break;
	}

	/* url may be in tmp */
	talloc_free(tmp);

	ERR_pop_to_mark();

	return out.result;
}
#endif	/* WITH_TLS && WITH_TLS_CA_POLICY_OCSP */
