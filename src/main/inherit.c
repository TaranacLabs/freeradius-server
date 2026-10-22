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
 * @file inherit.c
 * @brief Listen sockets handed over by a supervising process.
 *
 * A supervisor which owns the listen sockets starts the server with
 *
 *	RADIUSD_LISTEN_FDS=<fd>[,<fd>...]
 *	RADIUSD_READY_FD=<fd>
 *
 * Each listed descriptor is an already bound socket.  An auth, acct
 * or status listener whose address, port and socket type match one
 * of them uses it instead of opening its own, and one which matches
 * none is a startup error: the supervisor decides what the server
 * listens on.  So is a listed descriptor which no listener takes:
 * the supervisor would be holding a socket nobody reads.  Once the
 * server is about to process requests, it writes "READY\n" to the
 * ready descriptor and closes it.
 *
 * Both variables are removed from the environment, and every
 * descriptor is marked close-on-exec, so that no child process holds
 * a listen socket or learns about them.  Without the variables
 * nothing here does anything.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#define INHERIT_MAX_FDS	(16)

typedef struct inherit_fd_t {
	int		fd;
	int		type;		//!< SOCK_DGRAM, SOCK_STREAM
	fr_ipaddr_t	ipaddr;
	uint16_t	port;
	bool		taken;
} inherit_fd_t;

static inherit_fd_t	inherited[INHERIT_MAX_FDS];
static int		num_inherited = 0;
static bool		inherit_active = false;
static int		ready_fd = -1;

static int inherit_parse_fd(char const *name, char const *str, char **end)
{
	long	value;

	value = strtol(str, end, 10);
	if ((*end == str) || (value < 0) || (value > INT_MAX)) {
		ERROR("%s: invalid file descriptor in \"%s\"", name, str);
		return -1;
	}

	return (int) value;
}

static int inherit_cloexec(char const *name, int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);
	if ((flags < 0) || (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)) {
		ERROR("%s: file descriptor %d: %s", name, fd, fr_syserror(errno));
		return -1;
	}

	return 0;
}

static int inherit_add(int fd)
{
	struct stat		st;
	struct sockaddr_storage	salocal;
	socklen_t		salen = sizeof(salocal);
	socklen_t		optlen;
	inherit_fd_t		*entry;
	int			i;

	for (i = 0; i < num_inherited; i++) {
		if (inherited[i].fd == fd) {
			ERROR("RADIUSD_LISTEN_FDS: file descriptor %d is listed twice", fd);
			return -1;
		}
	}

	if (num_inherited == INHERIT_MAX_FDS) {
		ERROR("RADIUSD_LISTEN_FDS: more than %d file descriptors", INHERIT_MAX_FDS);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d: %s", fd, fr_syserror(errno));
		return -1;
	}

	if (!S_ISSOCK(st.st_mode)) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d is not a socket", fd);
		return -1;
	}

	entry = &inherited[num_inherited];
	memset(entry, 0, sizeof(*entry));
	entry->fd = fd;

	optlen = sizeof(entry->type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &entry->type, &optlen) < 0) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d: %s", fd, fr_syserror(errno));
		return -1;
	}

	memset(&salocal, 0, sizeof(salocal));
	if (getsockname(fd, (struct sockaddr *) &salocal, &salen) < 0) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d: %s", fd, fr_syserror(errno));
		return -1;
	}

	if (!fr_sockaddr2ipaddr(&salocal, salen, &entry->ipaddr, &entry->port)) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d has an unsupported address family", fd);
		return -1;
	}

	if (entry->port == 0) {
		ERROR("RADIUSD_LISTEN_FDS: file descriptor %d is not bound", fd);
		return -1;
	}

	if (inherit_cloexec("RADIUSD_LISTEN_FDS", fd) < 0) return -1;

	num_inherited++;

	return 0;
}

/** Read the inherited descriptors from the environment
 *
 * Called once, after the main configuration is read and before any
 * module is instantiated, so that no module sees the variables or
 * starts a child process which keeps a descriptor.
 *
 * @return
 *	- 0 on success, or if nothing is inherited.
 *	- -1 on error.
 */
int fr_inherit_init(void)
{
	char const	*fds, *ready, *p;
	char		*end;
	int		fd;

	fds = getenv("RADIUSD_LISTEN_FDS");
	ready = getenv("RADIUSD_READY_FD");
	if (!fds && !ready) return 0;

	/*
	 *	Checking the configuration opens no sockets.
	 */
	if (check_config) goto done;

	if (fds) {
		p = fds;
		while (*p) {
			fd = inherit_parse_fd("RADIUSD_LISTEN_FDS", p, &end);
			if (fd < 0) return -1;

			if (inherit_add(fd) < 0) return -1;

			if (*end == ',') end++;
			else if (*end) {
				ERROR("RADIUSD_LISTEN_FDS: invalid file descriptor in \"%s\"", fds);
				return -1;
			}
			p = end;
		}

		if (num_inherited == 0) {
			ERROR("RADIUSD_LISTEN_FDS: no file descriptors");
			return -1;
		}

		inherit_active = true;
	}

	if (ready) {
		fd = inherit_parse_fd("RADIUSD_READY_FD", ready, &end);
		if (fd < 0) return -1;
		if (*end) {
			ERROR("RADIUSD_READY_FD: invalid file descriptor in \"%s\"", ready);
			return -1;
		}

		if (inherit_cloexec("RADIUSD_READY_FD", fd) < 0) return -1;
		ready_fd = fd;
	}

	if (inherit_active) INFO("Using %d listen socket(s) from the supervising process", num_inherited);

done:
	unsetenv("RADIUSD_LISTEN_FDS");
	unsetenv("RADIUSD_READY_FD");

	return 0;
}

/** Whether listen sockets are inherited, rather than opened here
 *
 */
bool fr_inherit_active(void)
{
	return inherit_active;
}

/** Find the inherited socket for a listener
 *
 * @param[in] ipaddr	the listener binds to.
 * @param[in] port	the listener binds to.
 * @param[in] type	SOCK_DGRAM or SOCK_STREAM.
 * @return
 *	- the descriptor, which now belongs to the caller.
 *	- -1 if there is no such socket, with fr_strerror() saying why.
 */
int fr_inherit_take(fr_ipaddr_t const *ipaddr, uint16_t port, int type)
{
	int		i;
	inherit_fd_t	*entry;

	for (i = 0; i < num_inherited; i++) {
		entry = &inherited[i];

		if (entry->taken || (entry->type != type) || (entry->port != port) ||
		    (entry->ipaddr.af != ipaddr->af)) continue;

		if (ipaddr->af == AF_INET) {
			if (memcmp(&entry->ipaddr.ipaddr.ip4addr, &ipaddr->ipaddr.ip4addr,
				   sizeof(ipaddr->ipaddr.ip4addr)) != 0) continue;
		}
#ifdef HAVE_STRUCT_SOCKADDR_IN6
		else if (ipaddr->af == AF_INET6) {
			if ((entry->ipaddr.scope != ipaddr->scope) ||
			    (memcmp(&entry->ipaddr.ipaddr.ip6addr, &ipaddr->ipaddr.ip6addr,
				    sizeof(ipaddr->ipaddr.ip6addr)) != 0)) continue;

#ifdef IPV6_V6ONLY
			/*
			 *	listen_bind() makes '::' IPv6-only, and
			 *	it is too late to do that once bound.
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&ipaddr->ipaddr.ip6addr)) {
				int		on = 0;
				socklen_t	optlen = sizeof(on);

				if ((getsockopt(entry->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, &optlen) < 0) || !on) {
					fr_strerror_printf("inherited socket (fd %d) is not IPv6-only", entry->fd);
					return -1;
				}
			}
#endif
		}
#endif
		else continue;

		entry->taken = true;
		return entry->fd;
	}

	fr_strerror_printf("not provided by supervisor");
	return -1;
}

/** Tell the supervisor that the server is about to process requests
 *
 * An inherited socket which no listener took is an error: the
 * supervisor keeps it in its group, and datagrams sent to it would
 * never be read.
 *
 * @return
 *	- 0 on success.
 *	- -1 if an inherited socket is not used by any listener.
 */
int fr_inherit_ready(void)
{
	static char const	msg[] = "READY\n";
	char			buffer[128];
	int			i, unused = 0;

	for (i = 0; i < num_inherited; i++) {
		if (inherited[i].taken) continue;

		ERROR("Inherited socket %s port %u (fd %d) is not used by any listener",
		      inet_ntop(inherited[i].ipaddr.af, &inherited[i].ipaddr.ipaddr, buffer, sizeof(buffer)),
		      inherited[i].port, inherited[i].fd);
		unused++;
	}
	if (unused) return -1;

	if (ready_fd < 0) return 0;

	if (write(ready_fd, msg, sizeof(msg) - 1) < 0) {
		WARN("Failed telling the supervising process that we are ready: %s", fr_syserror(errno));
	}
	close(ready_fd);
	ready_fd = -1;

	return 0;
}
