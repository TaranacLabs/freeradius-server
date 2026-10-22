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
 * its chain has verified.  If the check cannot be made, the client is
 * rejected: there is no soft fail.
 *
 * This is not the "ocsp { }" section, which applies to every client
 * certificate, and the two cannot be used together.  The differences:
 *
 *  - no nonce, ever.  Microsoft's Online Responder answers "unauthorized"
 *    to a request with one.  Freshness comes from thisUpdate / nextUpdate,
 *    and a response without nextUpdate must be at most
 *    OCSP_MAX_AGE seconds old.
 *  - one deadline, FR_TLS_CA_POLICY_OCSP_TIMEOUT, for the whole exchange:
 *    waiting for a slot, connecting, sending and reading.  Name resolution
 *    is the exception: getaddrinfo() is not bounded by OpenSSL.
 *  - at most FR_TLS_CA_POLICY_OCSP_INFLIGHT requests at a time per
 *    tls-config, so that a slow or dead responder cannot take every worker
 *    thread.  A request waits at most FR_TLS_CA_POLICY_OCSP_SLOT_WAIT for
 *    a slot, out of the same deadline.
 *  - the signer of the response is verified against a store without CRL
 *    flags, with the client's verified chain as the untrusted
 *    certificates.  So a response signed by the CA itself verifies without
 *    a certificate in it, and a CA without a CRL does not break it.
 *  - every outcome other than "good" leaves one line, the verdict, in
 *    Module-Failure-Message.  See tls_ca_policy_ocsp().
 *
 * There is no cache of responses: one request per full handshake.
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

/** Requests in flight, per tls-config
 *
 * Both fields are used with conf->mutex held.  A talloc child of the
 * configuration, so that it goes with it.
 */
struct fr_tls_ca_policy_ocsp_slots_t {
	pthread_cond_t	cond;		//!< Signalled when a slot is given back.
	uint32_t	inflight;
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

static int _ocsp_slots_free(fr_tls_ca_policy_ocsp_slots_t *slots)
{
	pthread_cond_destroy(&slots->cond);
	return 0;
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
 * The store is read once, here.  ca_path_reload_interval does not re-read
 * it.  It goes in conf->ocsp_store, which is free as "ocsp { enable }" and
 * "ca_policy ... ocsp" cannot be used together, and is freed with the
 * configuration.
 *
 * Called after the mutex is initialised.
 *
 * @return 0 on success, -1 on error.
 */
int tls_ca_policy_ocsp_init(fr_tls_server_conf_t *conf)
{
	fr_tls_ca_policy_ocsp_slots_t	*slots;
	X509_STORE			*store;

	slots = talloc_zero(conf, fr_tls_ca_policy_ocsp_slots_t);
	if (!slots) {
		ERROR(LOG_PREFIX ": Out of memory");
		return -1;
	}
	if (pthread_cond_init(&slots->cond, NULL) != 0) {
		ERROR(LOG_PREFIX ": Failed initialising the OCSP slots of ca_policy");
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

/** Split an OCSP responder URL into host, port and path
 *
 * Only http: responses are signed, TLS adds nothing to them.  The scheme is
 * case-insensitive.  The port defaults to 80 and the path to "/"; a query
 * stays in the path.
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
	char	*copy, *h = NULL, *p = NULL, *u = NULL;
	int	ssl = 0, i, rcode = -1;

	if (strncasecmp(url, "https://", 8) == 0) {
		fr_strerror_printf("%s", https);
		return -1;
	}

	if (strncasecmp(url, "http://", 7) != 0) {
		fr_strerror_printf("the responder URL must start with http://");
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

	ERR_set_mark();
	if (!OCSP_parse_url(copy, &h, &p, &u, &ssl)) {
		char const *reason = ERR_reason_error_string(ERR_peek_last_error());

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

/** Take a slot for a request, waiting at most FR_TLS_CA_POLICY_OCSP_SLOT_WAIT
 *
 * The wait is against the wall clock, as are OpenSSL's own deadlines.
 *
 * @return true if a slot was taken, and must be given back.
 */
static bool ocsp_slot_take(fr_tls_server_conf_t *conf)
{
	fr_tls_ca_policy_ocsp_slots_t	*slots = conf->ca_policy_ocsp_slots;
	struct timeval			now;
	struct timespec			until;
	bool				taken = false;

	gettimeofday(&now, NULL);
	until.tv_sec = now.tv_sec + FR_TLS_CA_POLICY_OCSP_SLOT_WAIT;
	until.tv_nsec = now.tv_usec * 1000;

	pthread_mutex_lock(&conf->mutex);
	while (slots->inflight >= FR_TLS_CA_POLICY_OCSP_INFLIGHT) {
		if (pthread_cond_timedwait(&slots->cond, &conf->mutex, &until) != 0) break;	/* ETIMEDOUT */
	}
	if (slots->inflight < FR_TLS_CA_POLICY_OCSP_INFLIGHT) {
		slots->inflight++;
		taken = true;
	}
	pthread_mutex_unlock(&conf->mutex);

	return taken;
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
 * For a failure ("failed <class>"), the OpenSSL error behind it, if there
 * is a new one, is added: the last one on the queue, with its data (where
 * OCSP_basic_verify() puts the reason, and the HTTP client the server).
 * The detail of "revoked" and "unknown" is ours alone.
 */
static void ocsp_reject(ocsp_outcome_t *out, char const *verdict, int x509_err, bool openssl, char const *fmt, ...)
	CC_HINT(format (printf, 5, 6));
static void ocsp_reject(ocsp_outcome_t *out, char const *verdict, int x509_err, bool openssl, char const *fmt, ...)
{
	va_list		ap;
	size_t		len;
	unsigned long	code;
	char const	*file = NULL, *func = NULL, *data = NULL;
	int		line = 0, flags = 0;
	char		buf[256];

	out->result = FR_TLS_CA_POLICY_OCSP_FAILED;
	out->verdict = verdict;
	out->x509_err = x509_err;

	va_start(ap, fmt);
	vsnprintf(out->detail, sizeof(out->detail), fmt, ap);
	va_end(ap);

	if (!openssl) return;

	code = ERR_peek_last_error_all(&file, &line, &func, &data, &flags);
	if (!code || (code == out->err_before)) return;

	ERR_error_string_n(code, buf, sizeof(buf));
	len = strlen(out->detail);
	snprintf(out->detail + len, sizeof(out->detail) - len, " (%s%s%s)", buf,
		 ((flags & ERR_TXT_STRING) && data && *data) ? ": " : "",
		 ((flags & ERR_TXT_STRING) && data && *data) ? data : "");
}

#define REJECT_TRANSPORT(_fmt, ...)	ocsp_reject(&out, "failed transport", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)
#define REJECT_RESPONSE(_fmt, ...)	ocsp_reject(&out, "failed response", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)
#define REJECT_VERIFY(_fmt, ...)	ocsp_reject(&out, "failed verify", OCSP_X509_ERR_FAILED, true, _fmt, ## __VA_ARGS__)

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
 * https and ldap entries, and entries which do not parse, are skipped.
 *
 * @return 0 found, -1 none.
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
			RDEBUG2("(TLS) ocsp: skipping AIA OCSP entry \"%s\": %s", uri, fr_strerror());
			continue;
		}

		*url = talloc_strdup(ctx, uri);
		if (*url) rcode = 0;
		break;
	}
	X509_email_free(uris);

	return rcode;
}

/** Check a client certificate with OCSP, if a CA in its chain says so
 *
 * Called for depth 0 with ok = 1: the whole chain has verified, CRLs
 * included.  On a reject, the X509_STORE_CTX error is set so that the
 * client gets an alert which says why (certificate_revoked for a revoked
 * certificate), and one line goes to Module-Failure-Message:
 *
 *	(TLS) ocsp verdict revoked: reason <reason>, revoked at <time>; responder <url>
 *	(TLS) ocsp verdict unknown: the responder does not know the certificate; responder <url>
 *	(TLS) ocsp verdict failed <class>: <detail>; responder <url or none>
 *
 * <class> is "transport" (no HTTP 200 answer in time: name, connection,
 * timeout, HTTP error, too many requests in flight), "response" (an answer
 * which is not a successful OCSP response) or "verify" (the response, or
 * the certificate, could not be checked: no responder URL, no issuer,
 * signature or signer, no status for the certificate, times).  These words
 * are a contract with Taranac, as is the "ca_policy: N entries" marker.  Do
 * not change them without Taranac.
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
	int			status = -1, reason = -1, rcode;
	ASN1_GENERALIZEDTIME	*rev = NULL, *thisupd = NULL, *nextupd = NULL;
	char			t1[32], t2[32];
	VALUE_PAIR		*vp;

	deadline = time(NULL) + FR_TLS_CA_POLICY_OCSP_TIMEOUT;

	/*
	 *	Whatever OpenSSL leaves on the error queue from here on
	 *	must not be mistaken for an error of the handshake.
	 */
	ERR_set_mark();

	memset(&out, 0, sizeof(out));
	out.result = FR_TLS_CA_POLICY_OCSP_FAILED;
	out.err_before = ERR_peek_last_error();

	switch (tls_ca_policy_chain_find(request, conf, ctx, FR_TLS_CA_POLICY_OCSP, &line)) {
	case 0:
		RDEBUG2("(TLS) %s - ca_policy: no CA in the chain has OCSP configured", conf->name);
		out.result = FR_TLS_CA_POLICY_OCSP_NOT_NEEDED;
		goto done;

	case 1:
		break;

	default:
		REJECT_VERIFY("cannot evaluate the chain");
		goto done;
	}

	if (!conf->ocsp_store || !conf->ca_policy_ocsp_slots) {
		REJECT_VERIFY("per-CA OCSP is not initialised");
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
		REJECT_VERIFY("cannot evaluate the chain");
		goto done;
	}
	if (sk_X509_num(chain) > 1) {
		issuer = sk_X509_value(chain, 1);
	} else if ((X509_STORE_CTX_get1_issuer(&issuer_owned, ctx, leaf) == 1) && issuer_owned &&
		   (X509_cmp(issuer_owned, leaf) != 0)) {
		issuer = issuer_owned;
		certs = sk_X509_dup(chain);
		if (!certs || !sk_X509_push(certs, issuer)) {
			REJECT_VERIFY("out of memory");
			goto done;
		}
	}
	if (!issuer) {
		REJECT_VERIFY("no issuer certificate");
		goto done;
	}

	tmp = talloc_new(request);
	if (!tmp) {
		REJECT_VERIFY("out of memory");
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
	} else if (ocsp_aia_url(request, tmp, leaf, &url, &host, &port, &path) < 0) {
		url = NULL;
		REJECT_VERIFY("no OCSP responder URL (none configured for the CA, "
			      "no http OCSP entry in the certificate's AIA)");
		goto done;
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
		REJECT_VERIFY("cannot build the OCSP request");
		goto done;
	}
	if (!OCSP_request_add0_id(req, certid)) {
		OCSP_CERTID_free(certid);
		certid = NULL;
		REJECT_VERIFY("cannot build the OCSP request");
		goto done;
	}
	/* certid now belongs to req, and lives as long as it does */

	req_bio = ASN1_item_i2d_mem_bio(ASN1_ITEM_rptr(OCSP_REQUEST), (ASN1_VALUE const *) req);
	if (!req_bio) {
		REJECT_VERIFY("cannot encode the OCSP request");
		goto done;
	}

	/*
	 *	Taken before the name is resolved, so that a hung
	 *	resolver holds no more than the slots.
	 */
	if (!ocsp_slot_take(conf)) {
		REJECT_TRANSPORT("%d OCSP requests already in progress (the responder is slow or unreachable)",
				 FR_TLS_CA_POLICY_OCSP_INFLIGHT);
		goto done;
	}
	slot = true;

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
		REJECT_TRANSPORT("timed out waiting for a free OCSP slot");
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
		REJECT_TRANSPORT("cannot set up the HTTP request");
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
		REJECT_RESPONSE("the answer is not a DER OCSP response");
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
		if (!out.verdict) out.verdict = "failed verify";	/* not reached */
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
