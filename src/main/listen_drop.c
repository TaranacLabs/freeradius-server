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
 * @file listen_drop.c
 * @brief Log packets which the UDP receive path drops from a known client.
 *
 * Outside of debug mode, a packet from a known client which is
 * malformed, which has a code the socket does not accept, or which
 * lacks a Message-Authenticator the client requires, used to be
 * dropped without a trace.  These functions log one line per drop,
 * rate limited per source address.
 *
 * A listener with "refused_virtual_server" also runs each packet it
 * refuses from a known client through that virtual server: one whose
 * signature does not verify (listen_refused_request()), and one which
 * the receive path refuses (listen_refused_packet()).
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#include <ctype.h>

/*
 *	Daemon mode logs a dropped source at most once a second.  Sources
 *	share 256 slots, so a flood from many addresses still cannot fill
 *	the log faster than 256 lines a second.  Only the thread which
 *	reads the sockets uses it, as with the "unknown client" message.
 */
bool listen_drop_log_now(fr_ipaddr_t const *ipaddr)
{
	static struct {
		fr_ipaddr_t	ipaddr;
		time_t		when;
	} slots[256];
	uint32_t	hash;
	time_t		now;

	if (rad_debug_lvl) return true;

	hash = fr_hash(&ipaddr->ipaddr, (ipaddr->af == AF_INET) ? sizeof(ipaddr->ipaddr.ip4addr) :
		       sizeof(ipaddr->ipaddr.ip6addr)) & 0xff;
	now = time(NULL);

	if ((slots[hash].when == now) && (fr_ipaddr_cmp(&slots[hash].ipaddr, ipaddr) == 0)) return false;

	slots[hash].ipaddr = *ipaddr;
	slots[hash].when = now;
	return true;
}

static char const *decode_fail_str(decode_fail_t reason)
{
	switch (reason) {
	case DECODE_FAIL_MIN_LENGTH_PACKET:
	case DECODE_FAIL_MIN_LENGTH_FIELD:
		return "shorter than a RADIUS header";

	case DECODE_FAIL_MIN_LENGTH_MISMATCH:
		return "shorter than its Length field";

	case DECODE_FAIL_HEADER_OVERFLOW:
		return "attribute header overflows the packet";

	case DECODE_FAIL_UNKNOWN_PACKET_CODE:
		return "unknown packet code";

	case DECODE_FAIL_INVALID_ATTRIBUTE:
		return "attribute 0";

	case DECODE_FAIL_ATTRIBUTE_TOO_SHORT:
		return "attribute too short";

	case DECODE_FAIL_ATTRIBUTE_OVERFLOW:
		return "attribute data overflows the packet";

	case DECODE_FAIL_MA_INVALID_LENGTH:
		return "Message-Authenticator has an invalid length";

	case DECODE_FAIL_ATTRIBUTE_UNDERFLOW:
		return "attributes do not fill the packet";

	case DECODE_FAIL_TOO_MANY_ATTRIBUTES:
		return "too many attributes";

	case DECODE_FAIL_TOO_MANY_AUTH:
		return "EAP-Message with another authentication attribute";

	default:
		return "invalid header";
	}
}

/*
 *	The line logged for a dropped packet.  The same text is the
 *	Module-Failure-Message of the refused request.
 */
static void listen_drop_text(char *out, size_t outlen, rad_listen_t *listener, fr_ipaddr_t const *ipaddr,
			     uint16_t src_port, RADCLIENT const *client, int code, decode_fail_t reason,
			     RADIUS_PACKET const *packet)
{
	char	name[256], src[INET6_ADDRSTRLEN];

	listener->print(listener, name, sizeof(name));
	inet_ntop(ipaddr->af, &ipaddr->ipaddr, src, sizeof(src));

	switch (reason) {
	case DECODE_FAIL_NONE:
		snprintf(out, outlen, "Ignoring request to %s from client %s port %d: packet code %d (%s) "
			 "is not accepted here, client %s", name, src, src_port, code,
			 (is_radius_code(code) && isalpha((uint8_t) fr_packet_codes[code][0])) ?
			 fr_packet_codes[code] : "unknown", client->shortname);
		break;

	case DECODE_FAIL_MA_MISSING:
		/*
		 *	The order of the checks in rad_packet_ok().  An
		 *	EAP-Message requires a Message-Authenticator
		 *	whatever the client says.
		 */
		if (client->require_ma == FR_BOOL_TRUE) {
			snprintf(out, outlen, "Ignoring request to %s from client %s port %d: no "
				 "Message-Authenticator, which client %s requires", name, src, src_port,
				 client->shortname);

		} else if (code == PW_CODE_STATUS_SERVER) {
			snprintf(out, outlen, "Ignoring request to %s from client %s port %d: Status-Server without "
				 "Message-Authenticator, client %s", name, src, src_port, client->shortname);

		} else if (packet && packet->eap_message) {
			snprintf(out, outlen, "Ignoring request to %s from client %s port %d: EAP-Message without "
				 "Message-Authenticator, client %s", name, src, src_port, client->shortname);

		} else if (packet && packet->proxy_state) {
			snprintf(out, outlen, "Ignoring request to %s from client %s port %d: Proxy-State without "
				 "Message-Authenticator, which client %s refuses (limit_proxy_state)",
				 name, src, src_port, client->shortname);

		} else {
			snprintf(out, outlen, "Ignoring request to %s from client %s port %d: Proxy-State or "
				 "EAP-Message without Message-Authenticator, client %s",
				 name, src, src_port, client->shortname);
		}
		break;

	default:
		snprintf(out, outlen, "Ignoring request to %s from client %s port %d: malformed packet (%s), "
			 "client %s", name, src, src_port, decode_fail_str(reason), client->shortname);
		break;
	}
}

/** Log a packet dropped by the UDP receive path
 *
 * @param listener	the packet was read from.
 * @param ipaddr	source address of the packet.
 * @param src_port	source port of the packet.
 * @param client	the packet came from.  NULL to look it up by address:
 *			nothing is logged for an unknown source.
 * @param code		of the packet, used when reason is DECODE_FAIL_NONE
 *			(the socket does not accept that code) or
 *			DECODE_FAIL_MA_MISSING.
 * @param reason	why rad_recv() refused the packet, DECODE_FAIL_NONE
 *			for a packet code the socket does not accept, or
 *			DECODE_FAIL_MAX for an invalid header.
 * @param packet	which rad_recv_reason() refused, or NULL.  Says
 *			which attribute lacks its Message-Authenticator.
 */
void listen_drop_log(rad_listen_t *listener, fr_ipaddr_t const *ipaddr, uint16_t src_port,
		     RADCLIENT const *client, int code, decode_fail_t reason, RADIUS_PACKET const *packet)
{
	listen_socket_t	*sock = listener->data;
	char		text[1024];

	if (!client) {
		client = client_find(sock->clients, ipaddr, sock->proto);
		if (!client && client_nas_id_configured()) client = client_nas_id_covering(sock->clients, ipaddr);
		if (!client) return;
	}

	if (!listen_drop_log_now(ipaddr)) return;

	listen_drop_text(text, sizeof(text), listener, ipaddr, src_port, client, code, reason, packet);
	radlog(L_ERR, "%s", text);
}

/** Whether an attribute's value depends on the shared secret
 *
 * User-Password, Tunnel-Password, the MS-MPPE keys and the like are
 * encrypted with the secret, and Message-Authenticator is signed
 * with it.  An attribute which did not decrypt is left unknown, so
 * its number is looked up again.
 */
static bool refused_secret_dependent(DICT_ATTR const *da)
{
	if (da->flags.is_unknown) {
		DICT_ATTR const *known = dict_attrbyvalue(da->attr, da->vendor);

		if (known) da = known;
	}

	if (!da->vendor && (da->attr == PW_MESSAGE_AUTHENTICATOR)) return true;

	return (da->flags.encrypt != FLAG_ENCRYPT_NONE);
}

/*
 *	Decode the attributes of a refused packet without trusting
 *	them, and remove those which depend on the shared secret.
 *	If decoding fails, the packet has no attributes beyond those
 *	it already had.
 */
static void refused_decode(REQUEST *request)
{
	VALUE_PAIR	*vp, **last;

	(void) rad_decode(request->packet, NULL, request->client->secret);

	/*
	 *	Values encrypted with the wrong secret are noise.
	 *	Everything else is as the client sent it.
	 */
	for (last = &request->packet->vps; (vp = *last) != NULL; ) {
		if (refused_secret_dependent(vp->da)) {
			*last = vp->next;
			vp->next = NULL;
			talloc_free(vp);
			continue;
		}
		last = &vp->next;
	}
}

/*
 *	Run the request through "refused_virtual_server".  The
 *	caller drops it without a response.
 */
static void refused_run(REQUEST *request, char const *server)
{
	request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	request->server = server;

	RDEBUG("Refused request, running it through server %s", request->server);
	rdebug_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);
	RDEBUG("server %s {", request->server);
	(void) process_authorize(0, request);
	RDEBUG("} # server %s", request->server);

#ifdef WITH_COA
	TALLOC_FREE(request->coa);
#endif
}

/*
 *	Only UDP auth and acct sockets take the option, and only
 *	theirs is a listen_socket_t.
 */
static char const *refused_server(rad_listen_t const *listener)
{
	listen_socket_t const *sock;

	if (!listener || ((listener->type != RAD_LISTEN_AUTH) && (listener->type != RAD_LISTEN_ACCT))) return NULL;

	sock = listener->data;
	return sock->refused_server;
}

/** Run a refused request through the listener's "refused_virtual_server"
 *
 * The request is not answered whatever the virtual server does: the
 * caller drops it as before.  It is not proxied either (only the
 * authorize section runs), and a CoA request it originates is
 * freed here, before request_done() could send it.
 *
 * @param request	which the listener refused.  Its packet has no
 *			attributes yet.
 * @param reason	why, the value of Refused-Reason.
 * @param message	the server's own words, Module-Failure-Message.
 */
void listen_refused_request(REQUEST *request, refused_reason_t reason, char const *message)
{
	char const	*server;
	VALUE_PAIR	*vp;

	server = refused_server(request->listener);
	if (!server) return;

	/*
	 *	rad_verify() left the Message-Authenticator, and for an
	 *	Accounting-Request the Request Authenticator, zeroed in
	 *	packet->data.  rad_decode() takes the authenticator from
	 *	packet->vector, which is intact, and the
	 *	Message-Authenticator is removed.
	 */
	if (reason == REFUSED_REASON_KEY_MISMATCH) refused_decode(request);

	vp = radius_pair_create(request->packet, &request->packet->vps, PW_REFUSED_REASON, 0);
	vp->vp_integer = reason;

	vp = radius_pair_create(request->packet, &request->packet->vps, PW_MODULE_FAILURE_MESSAGE, 0);
	fr_pair_value_strcpy(vp, message);

	refused_run(request, server);
}

/** Hand a packet which the UDP receive path refuses to the worker threads
 *
 * The packet becomes a request like any other, subject to the same
 * duplicate detection, max_requests, max_pps and thread pool queue,
 * with rad_refused() as its handler.  request_pre_handler() runs it
 * through "refused_virtual_server" in a worker thread and drops it
 * without a response.  The thread which reads the sockets only
 * builds the text and two attributes.
 *
 * @param ctx		the packet is allocated in.  Freed here unless a
 *			request now owns it.
 * @param listener	the packet was read from.
 * @param packet	which rad_recv_reason() refused, or which has a
 *			code the socket does not accept.
 * @param client	the packet came from.
 * @param reason	DECODE_FAIL_NONE for a packet code the socket does
 *			not accept, otherwise why rad_recv_reason()
 *			refused it.
 * @param decodable	whether rad_decode() may read the attributes.
 * @return 1 if a request now owns ctx, 0 otherwise.
 */
static int refused_hand_over(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
			     RADCLIENT *client, decode_fail_t reason, bool decodable)
{
	VALUE_PAIR	*vp;
	char		text[1024];

	listen_drop_text(text, sizeof(text), listener, &packet->src_ipaddr, packet->src_port, client,
			 packet->code, reason, packet);

	/*
	 *	The worker decodes only a packet which still has its
	 *	data: the attributes of any other one are not
	 *	well-formed.
	 */
	if (!decodable) {
		TALLOC_FREE(packet->data);
		packet->data_len = 0;
	}

	vp = fr_pair_afrom_num(packet, PW_REFUSED_REASON, 0);
	if (!vp) goto fail;
	switch (reason) {
	case DECODE_FAIL_NONE:
		vp->vp_integer = REFUSED_REASON_WRONG_PORT;
		break;

	case DECODE_FAIL_MA_MISSING:
		vp->vp_integer = REFUSED_REASON_MESSAGE_AUTHENTICATOR_MISSING;
		break;

	default:
		vp->vp_integer = REFUSED_REASON_MALFORMED_REQUEST;
		break;
	}
	fr_pair_add(&packet->vps, vp);

	vp = fr_pair_afrom_num(packet, PW_MODULE_FAILURE_MESSAGE, 0);
	if (!vp) goto fail;
	fr_pair_value_strcpy(vp, text);
	fr_pair_add(&packet->vps, vp);

	if (request_receive(ctx, listener, packet, client, rad_refused)) return 1;

fail:
	talloc_free(ctx);
	return 0;
}

/** Hand a packet which rad_recv_reason() refused to "refused_virtual_server"
 *
 * Without the option, frees it.
 *
 * @param ctx		the packet is allocated in.  Freed here unless a
 *			request now owns it.
 * @param listener	the packet was read from.
 * @param packet	which rad_recv_reason() refused.
 * @param client	the packet came from.
 * @param reason	why rad_recv_reason() refused it.
 * @return 1 if a request now owns ctx, 0 otherwise.
 */
int listen_refused_packet(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet, RADCLIENT *client,
			  decode_fail_t reason)
{
	if (!refused_server(listener)) {
		talloc_free(ctx);
		return 0;
	}

	return refused_hand_over(ctx, listener, packet, client, reason, (reason == DECODE_FAIL_MA_MISSING));
}

/** Read a packet with a code the socket does not accept, for "refused_virtual_server"
 *
 * Without the option, discards the datagram as before.  Otherwise
 * reads it, without the Message-Authenticator checks of its client:
 * they are for the codes the socket accepts.
 *
 * @param listener	the packet is waiting on.
 * @param client	the packet came from.
 * @return 1 if a request now owns the packet, 0 otherwise.
 */
int listen_refused_wrong_port(rad_listen_t *listener, RADCLIENT *client)
{
	TALLOC_CTX	*ctx;
	RADIUS_PACKET	*packet, *refused;
	decode_fail_t	reason;

	if (!refused_server(listener)) {
		rad_recv_discard(listener->fd);
		return 0;
	}

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		rad_recv_discard(listener->fd);
		return 0;
	}
	talloc_set_name_const(ctx, "refused_listener_pool");

	packet = rad_recv_reason(ctx, listener->fd, 0, &reason, &refused);
	if (packet) return refused_hand_over(ctx, listener, packet, client, DECODE_FAIL_NONE, true);
	if (refused) return refused_hand_over(ctx, listener, refused, client, DECODE_FAIL_NONE,
					      (reason == DECODE_FAIL_MA_MISSING));

	talloc_free(ctx);
	return 0;
}

/** The handler of a request made by listen_refused_packet() or listen_refused_wrong_port()
 *
 * request_pre_handler() calls it in a worker thread instead of
 * decoding the packet, then drops the request without a response.
 * The packet carries Refused-Reason and Module-Failure-Message, and
 * still has its data only if its attributes are well-formed.  They
 * are decoded without verification, as for Key-Mismatch.
 *
 * @param request	to run through "refused_virtual_server".
 * @return RLM_MODULE_HANDLED.
 */
int rad_refused(REQUEST *request)
{
	char const	*server;

	/*
	 *	The listener counted the packet as malformed or of an
	 *	unknown type; the request is not counted again.
	 */
	request->options |= RAD_REQUEST_OPTION_STATS;

	server = refused_server(request->listener);
	if (!server) return RLM_MODULE_HANDLED;

	if (request->packet->data) refused_decode(request);

	refused_run(request, server);

	return RLM_MODULE_HANDLED;
}
