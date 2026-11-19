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
 * A listener with "refused_virtual_server" also runs each request it
 * refuses through that virtual server, see listen_refused_request().
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
 */
void listen_drop_log(rad_listen_t *listener, fr_ipaddr_t const *ipaddr, uint16_t src_port,
		     RADCLIENT const *client, int code, decode_fail_t reason)
{
	listen_socket_t	*sock = listener->data;
	char		name[256], src[INET6_ADDRSTRLEN];

	if (!client) {
		client = client_find(sock->clients, ipaddr, sock->proto);
		if (!client && client_nas_id_configured()) client = client_nas_id_covering(sock->clients, ipaddr);
		if (!client) return;
	}

	if (!listen_drop_log_now(ipaddr)) return;

	listener->print(listener, name, sizeof(name));
	inet_ntop(ipaddr->af, &ipaddr->ipaddr, src, sizeof(src));

	switch (reason) {
	case DECODE_FAIL_NONE:
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: packet code %d (%s) "
		       "is not accepted here, client %s", name, src, src_port, code,
		       (is_radius_code(code) && isalpha((uint8_t) fr_packet_codes[code][0])) ?
		       fr_packet_codes[code] : "unknown", client->shortname);
		break;

	case DECODE_FAIL_MA_MISSING:
		if (client->require_ma == FR_BOOL_TRUE) {
			radlog(L_ERR, "Ignoring request to %s from client %s port %d: no Message-Authenticator, "
			       "which client %s requires", name, src, src_port, client->shortname);

		} else if (code == PW_CODE_STATUS_SERVER) {
			radlog(L_ERR, "Ignoring request to %s from client %s port %d: Status-Server without "
			       "Message-Authenticator, client %s", name, src, src_port, client->shortname);

		} else {
			radlog(L_ERR, "Ignoring request to %s from client %s port %d: Proxy-State without "
			       "Message-Authenticator, which client %s refuses (limit_proxy_state)",
			       name, src, src_port, client->shortname);
		}
		break;

	default:
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: malformed packet (%s), client %s",
		       name, src, src_port, decode_fail_str(reason), client->shortname);
		break;
	}
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
	listen_socket_t	*sock;
	VALUE_PAIR	*vp, **last;

	/*
	 *	Only UDP auth and acct sockets take the option, and only
	 *	theirs is a listen_socket_t.
	 */
	if (!request->listener ||
	    ((request->listener->type != RAD_LISTEN_AUTH) && (request->listener->type != RAD_LISTEN_ACCT))) return;

	sock = request->listener->data;
	if (!sock->refused_server) return;

	if (reason == REFUSED_REASON_KEY_MISMATCH) {
		/*
		 *	Decode what we can without trusting it.  rad_verify()
		 *	left the Message-Authenticator, and for an
		 *	Accounting-Request the Request Authenticator, zeroed
		 *	in packet->data.  rad_decode() takes the
		 *	authenticator from packet->vector, which is intact,
		 *	and the Message-Authenticator is removed below.  If
		 *	decoding fails, the packet has no attributes.
		 */
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

	vp = radius_pair_create(request->packet, &request->packet->vps, PW_REFUSED_REASON, 0);
	vp->vp_integer = reason;

	vp = radius_pair_create(request->packet, &request->packet->vps, PW_MODULE_FAILURE_MESSAGE, 0);
	fr_pair_value_strcpy(vp, message);

	request->username = fr_pair_find_by_num(request->packet->vps, PW_USER_NAME, 0, TAG_ANY);
	request->server = sock->refused_server;

	RDEBUG("Refused request, running it through server %s", request->server);
	rdebug_pair_list(L_DBG_LVL_1, request, request->packet->vps, NULL);
	RDEBUG("server %s {", request->server);
	(void) process_authorize(0, request);
	RDEBUG("} # server %s", request->server);

#ifdef WITH_COA
	TALLOC_FREE(request->coa);
#endif
}
