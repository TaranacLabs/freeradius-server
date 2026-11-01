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
 * @file listen_nas_id.c
 * @brief Find the client of a UDP packet by its NAS-Identifier.
 *
 * The receive side of "identify_by = nas_identifier" (client_nas_id.c):
 * the NAS-Identifier is read from the datagram waiting on the socket,
 * before rad_recv() reads and checks it with the secret of the client
 * returned here.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#define NAS_ID_HDR_LEN	(20)
#define NAS_ID_MAX_LEN	(253)

/*
 *	Read the NAS-Identifier from the datagram at the head of the
 *	socket queue, leaving it there.
 *
 *	Returns -1 for a malformed packet, otherwise the number of
 *	NAS-Identifier attributes.  The value is set when there is
 *	exactly one.
 */
static int nas_id_peek(int fd, uint8_t *buffer, size_t bufsize, uint8_t const **value, size_t *len)
{
	ssize_t		data_len;
	size_t		packet_len;
	uint8_t const	*attr, *end;
	int		count = 0;

	data_len = recv(fd, buffer, bufsize, MSG_PEEK);
	if (data_len < NAS_ID_HDR_LEN) return -1;

	packet_len = (buffer[2] << 8) | buffer[3];
	if ((packet_len < NAS_ID_HDR_LEN) || (packet_len > (size_t) data_len)) return -1;

	attr = buffer + NAS_ID_HDR_LEN;
	end = buffer + packet_len;

	while (attr < end) {
		if ((end - attr) < 2) return -1;
		if ((attr[1] < 2) || (attr[1] > (end - attr))) return -1;

		if (attr[0] == PW_NAS_IDENTIFIER) {
			count++;
			*value = attr + 2;
			*len = attr[1] - 2;
		}

		attr += attr[1];
	}

	return count;
}

/*
 *	Daemon mode logs a dropped source at most once a second.  Sources
 *	share 256 slots, so a flood from many addresses still cannot fill
 *	the log faster than 256 lines a second.  Only the thread which
 *	reads the sockets uses it, as with the "unknown client" message.
 */
static bool nas_id_log_now(fr_ipaddr_t const *ipaddr)
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

/** Find the client of a UDP authentication or accounting packet
 *
 * Wraps client_listener_find(): when there are identify_by clients, the
 * NAS-Identifier of the packet waiting on the socket can select one of
 * their entries.  Otherwise the lookup is the usual one, by address.
 */
RADCLIENT *client_nas_id_listener_find(rad_listen_t *listener, fr_ipaddr_t const *ipaddr, uint16_t src_port)
{
	listen_socket_t	*sock = listener->data;
	uint8_t		buffer[MAX_PACKET_LEN];
	uint8_t const	*value = NULL;
	size_t		len = 0;
	int		count;
	RADCLIENT	*client, *parent;
	char		name[256], src[INET6_ADDRSTRLEN], nas_id[NAS_ID_MAX_LEN * 4 + 3];

	if (!client_nas_id_configured() || (sock->proto != IPPROTO_UDP)) {
		return client_listener_find(listener, ipaddr, src_port);
	}

	count = nas_id_peek(listener->fd, buffer, sizeof(buffer), &value, &len);
	if (count == 1) {
		client = client_nas_id_find(sock->clients, ipaddr, value, len);
		if (client) return client;
	}

	/*
	 *	No entry: the clients which have a secret, as usual.
	 */
	if (client_find(sock->clients, ipaddr, sock->proto)) {
		return client_listener_find(listener, ipaddr, src_port);
	}

	parent = client_nas_id_covering(sock->clients, ipaddr);
	if (!parent) return client_listener_find(listener, ipaddr, src_port);

	if (!nas_id_log_now(ipaddr)) return NULL;

	listener->print(listener, name, sizeof(name));
	inet_ntop(ipaddr->af, &ipaddr->ipaddr, src, sizeof(src));

	switch (count) {
	case 1:
		fr_prints(nas_id, sizeof(nas_id), (char const *) value, len, '"');
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: NAS-Identifier \"%s\" "
		       "matches no nas_identifier of client %s", name, src, src_port, nas_id, parent->shortname);
		break;

	case 0:
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: no NAS-Identifier, "
		       "which client %s needs", name, src, src_port, parent->shortname);
		break;

	case -1:
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: malformed packet",
		       name, src, src_port);
		break;

	default:
		radlog(L_ERR, "Ignoring request to %s from client %s port %d: %d NAS-Identifier attributes, "
		       "client %s needs exactly one", name, src, src_port, count, parent->shortname);
		break;
	}

	return NULL;
}
