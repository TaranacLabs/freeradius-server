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
 * @file client_nas_id.c
 * @brief Clients identified by source address and NAS-Identifier.
 *
 * A client section with "identify_by = nas_identifier" holds
 * "nas_identifier <value> { ... }" subsections, each with its own
 * secret, shortname and virtual server:
 *
 *	client vpn-gateways {
 *		ipaddr = 192.0.2.0/24
 *		identify_by = nas_identifier
 *		nas_identifier "vpn-1" {
 *			secret = "..."
 *			shortname = "vpn-1"
 *		}
 *		nas_identifier "ssh-bastion" {
 *			secret = "..."
 *		}
 *	}
 *
 * When a UDP authentication or accounting packet arrives, its
 * NAS-Identifier is read from the raw packet (listen_nas_id.c).  NAS-Identifier is plain
 * text, so no secret is needed to read it.  The entry it names (in the
 * client with the longest prefix that covers the source address) becomes
 * the client of the request, and the packet is then verified with that
 * entry's secret exactly as for any other client.  Message-Authenticator
 * is required in Access-Request and Status-Server packets from such an
 * entry: without it, nothing in an Access-Request proves the sender
 * knows the secret of the entry it names.
 *
 * Lookup order for a packet from address A carrying NAS-Identifier N:
 *
 *  1. the "nas_identifier N" entry of the identify_by client which covers
 *     A with the longest prefix;
 *  2. otherwise, the usual longest-prefix match among the clients which
 *     have a secret: ordinary clients, and identify_by clients which also
 *     have a "secret" of their own;
 *  3. otherwise the packet is dropped as coming from an unknown client.
 *
 * An identify_by client without a secret of its own is invisible to
 * the address lookup in step 2, so it does not hide a shorter-prefix
 * client from packets it has no entry for.
 *
 * This file holds the configuration and the lookups.  Entries are
 * created when the configuration is read, and never change afterwards.
 * Lookups only read them, so the receive path needs no locking.
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#define NAS_ID_MAX_LEN	(253)

typedef struct nas_id_entry nas_id_entry_t;

/** One "nas_identifier <value> { ... }" subsection
 *
 * Entries with the same value in different clients are chained from the
 * one which is in the tree.
 */
struct nas_id_entry {
	char const		*value;		//!< The NAS-Identifier.
	size_t			len;		//!< Its length.
	RADCLIENT		*parent;	//!< The identify_by client.
	RADCLIENT		*client;	//!< The client the request gets.
	nas_id_entry_t		*next;		//!< Same value, other parent.
};

/** Per identify_by client
 *
 */
struct client_nas_id {
	RADCLIENT		*parent;
	unsigned int		count;		//!< Number of entries.
	client_nas_id_t		*prev;		//!< Every identify_by client.
	client_nas_id_t		*next;
};

/*
 *	Both are written only while the configuration is read (and
 *	when it is freed at exit), and only read afterwards.
 */
static rbtree_t		*nas_id_tree = NULL;
static client_nas_id_t	*nas_id_clients = NULL;

typedef struct {
	char const		*secret;
	char const		*shortname;
	char const		*nas_type;
	char const		*server;
	char const		*require_ma;
} nas_id_conf_t;

static const CONF_PARSER nas_id_config[] = {
	{ "secret", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, nas_id_conf_t, secret), NULL },
	{ "shortname", FR_CONF_OFFSET(PW_TYPE_STRING, nas_id_conf_t, shortname), NULL },
	{ "nas_type", FR_CONF_OFFSET(PW_TYPE_STRING, nas_id_conf_t, nas_type), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, nas_id_conf_t, server), NULL },
	{ "require_message_authenticator", FR_CONF_OFFSET(PW_TYPE_STRING, nas_id_conf_t, require_ma), NULL },

	CONF_PARSER_TERMINATOR
};

static int nas_id_cmp(void const *one, void const *two)
{
	nas_id_entry_t const *a = one;
	nas_id_entry_t const *b = two;
	int rcode;

	if (a->len < b->len) return -1;
	if (a->len > b->len) return +1;

	rcode = memcmp(a->value, b->value, a->len);
	if (rcode < 0) return -1;

	return (rcode > 0);
}

static int nas_id_entry_free(nas_id_entry_t *entry)
{
	nas_id_entry_t *head, **last;

	if (!nas_id_tree) return 0;

	head = rbtree_finddata(nas_id_tree, entry);
	if (!head) return 0;

	if (head == entry) {
		rbtree_deletebydata(nas_id_tree, entry);
		if (entry->next) {
			rbtree_insert(nas_id_tree, entry->next);
		} else if (rbtree_num_elements(nas_id_tree) == 0) {
			rbtree_free(nas_id_tree);
			nas_id_tree = NULL;
		}
		return 0;
	}

	for (last = &head->next; *last; last = &(*last)->next) {
		if (*last == entry) {
			*last = entry->next;
			break;
		}
	}

	return 0;
}

static int client_nas_id_free(client_nas_id_t *cn)
{
	if (cn->prev) {
		cn->prev->next = cn->next;
	} else if (nas_id_clients == cn) {
		nas_id_clients = cn->next;
	}
	if (cn->next) cn->next->prev = cn->prev;

	return 0;
}

/*
 *	Does client "parent" cover "ipaddr"?  Same comparison as
 *	client_find().
 */
static bool nas_id_covers(RADCLIENT const *parent, fr_ipaddr_t const *ipaddr)
{
	fr_ipaddr_t masked;

	if (parent->ipaddr.af != ipaddr->af) return false;

	masked = *ipaddr;
	fr_ipaddr_mask(&masked, parent->ipaddr.prefix);

	return (fr_ipaddr_cmp(&masked, &parent->ipaddr) == 0);
}

static bool nas_id_usable(RADCLIENT const *parent, RADCLIENT_LIST const *clients)
{
	if (parent->list != clients) return false;
#ifdef WITH_DYNAMIC_CLIENTS
	if (parent->dynamic) return false;
#endif
	return true;
}

/** Parse one "nas_identifier <value> { ... }" subsection
 *
 */
static int nas_id_entry_parse(RADCLIENT *c, client_nas_id_t *cn, CONF_SECTION *subcs, bool in_server)
{
	char const	*value;
	nas_id_conf_t	conf;
	nas_id_entry_t	*entry, *head, *e;
	RADCLIENT	*sub;

	value = cf_section_name2(subcs);
	if (!value || !*value) {
		cf_log_err_cs(subcs, "nas_identifier must have a non-empty value");
		return -1;
	}

	if (strlen(value) > NAS_ID_MAX_LEN) {
		cf_log_err_cs(subcs, "nas_identifier is longer than %d characters", NAS_ID_MAX_LEN);
		return -1;
	}

	memset(&conf, 0, sizeof(conf));
	if (cf_section_parse(subcs, &conf, nas_id_config) < 0) {
		cf_log_err_cs(subcs, "Error parsing nas_identifier \"%s\"", value);
		return -1;
	}

	if (!conf.secret || !*conf.secret) {
		cf_log_err_cs(subcs, "nas_identifier \"%s\": secret must be at least 1 character long", value);
		return -1;
	}

	/*
	 *	Without Message-Authenticator, an Access-Request proves
	 *	nothing about the secret of the entry it names.
	 */
	if (conf.require_ma) {
		fr_bool_auto_t ma = FR_BOOL_FALSE;

		if ((fr_bool_auto_parse(cf_pair_find(subcs, "require_message_authenticator"), &ma, conf.require_ma) < 0) ||
		    (ma != FR_BOOL_TRUE)) {
			cf_log_err_cs(subcs, "nas_identifier \"%s\": require_message_authenticator cannot be "
				      "anything but \"yes\"", value);
			return -1;
		}
	}

	if (conf.server) {
		if (in_server) {
			cf_log_err_cs(subcs, "Clients inside of an server section cannot point to a server");
			return -1;
		}

		if (main_config.config &&
		    !cf_section_sub_find_name2(main_config.config, "server", conf.server)) {
			cf_log_err_cs(subcs, "nas_identifier \"%s\": virtual server %s does not exist",
				      value, conf.server);
			return -1;
		}
	}

	/*
	 *	The request gets a client of its own, so that everything
	 *	which reads request->client sees this entry: the secret,
	 *	%{client:...}, Client-Shortname, statistics.  Whatever
	 *	the entry does not set comes from the enclosing client.
	 */
	sub = talloc_zero(c, RADCLIENT);
	if (!sub) return -1;

	sub->ipaddr = c->ipaddr;
	sub->src_ipaddr = c->src_ipaddr;
	sub->longname = c->longname;
	sub->secret = conf.secret;
	sub->shortname = conf.shortname ? conf.shortname : value;
	sub->nas_type = conf.nas_type ? conf.nas_type : c->nas_type;
	sub->server = conf.server ? conf.server : c->server;
	sub->login = c->login;
	sub->password = c->password;
	sub->require_ma = FR_BOOL_TRUE;
	sub->limit_proxy_state = FR_BOOL_FALSE;
	sub->protocol_error = c->protocol_error;
	sub->response_window = c->response_window;
	sub->proto = c->proto;
	sub->cs = subcs;

	if (strlen(sub->secret) < 12) {
		WARN("Shared secret for client %s is short, and likely can be broken by an attacker.",
		     sub->shortname);
	}

	entry = talloc_zero(sub, nas_id_entry_t);
	if (!entry) return -1;

	entry->value = value;
	entry->len = strlen(value);
	entry->parent = c;
	entry->client = sub;

	if (!nas_id_tree) {
		nas_id_tree = rbtree_create(NULL, nas_id_cmp, NULL, RBTREE_FLAG_NONE);
		if (!nas_id_tree) return -1;
	}

	head = rbtree_finddata(nas_id_tree, entry);
	if (!head) {
		if (!rbtree_insert(nas_id_tree, entry)) return -1;
	} else {
		for (e = head; e; e = e->next) {
			if (e->parent == c) {
				cf_log_err_cs(subcs, "Duplicate nas_identifier \"%s\"", value);
				return -1;
			}
		}

		entry->next = head->next;
		head->next = entry;
	}
	talloc_set_destructor(entry, nas_id_entry_free);

	cn->count++;
	return 0;
}

/** Parse "identify_by" and the "nas_identifier" subsections of a client
 *
 * @param c the client being parsed by client_afrom_cs().
 * @param cs its section.
 * @param in_server whether the client is in a server section.
 * @return
 *	- 0 the client is an ordinary client, or an identify_by client
 *	  with a secret of its own: carry on parsing it.
 *	- 1 an identify_by client without a secret: it is complete.
 *	- -1 on error.
 */
int client_nas_id_parse(RADCLIENT *c, CONF_SECTION *cs, bool in_server)
{
	CONF_PAIR	*cp;
	CONF_SECTION	*subcs;
	char const	*value;
	client_nas_id_t	*cn;

	cp = cf_pair_find(cs, "identify_by");
	if (!cp) {
		if (cf_section_sub_find(cs, "nas_identifier")) {
			cf_log_err_cs(cs, "\"nas_identifier\" needs \"identify_by = nas_identifier\"");
			return -1;
		}
		return 0;
	}

	value = cf_pair_value(cp);
	if (!value || (strcmp(value, "nas_identifier") != 0)) {
		cf_log_err_cs(cs, "Invalid value for \"identify_by\", expected \"nas_identifier\"");
		return -1;
	}

	/*
	 *	The NAS-Identifier is read from datagrams.  A TCP or
	 *	TLS client is one connection, and a dynamic client is
	 *	created from the first packet: neither fits.
	 */
	if (c->proto != IPPROTO_UDP) {
		cf_log_err_cs(cs, "\"identify_by = nas_identifier\" needs \"proto = udp\"");
		return -1;
	}

	if (cf_section_sub_find(cs, "tls")) {
		cf_log_err_cs(cs, "\"identify_by = nas_identifier\" cannot be used with \"tls\"");
		return -1;
	}

#ifdef WITH_DYNAMIC_CLIENTS
	if (c->client_server || c->dynamic) {
		cf_log_err_cs(cs, "\"identify_by = nas_identifier\" cannot be used with dynamic clients");
		return -1;
	}
#endif

#ifdef WITH_COA
	if (cf_pair_find(cs, "coa_server") || cf_section_sub_find(cs, "coa_server")) {
		cf_log_err_cs(cs, "\"identify_by = nas_identifier\" cannot be used with \"coa_server\"");
		return -1;
	}
#endif

	cn = talloc_zero(c, client_nas_id_t);
	if (!cn) return -1;
	cn->parent = c;

	for (subcs = cf_subsection_find_next(cs, NULL, "nas_identifier");
	     subcs;
	     subcs = cf_subsection_find_next(cs, subcs, "nas_identifier")) {
		if (nas_id_entry_parse(c, cn, subcs, in_server) < 0) return -1;
	}

	if (!cn->count) {
		cf_log_err_cs(cs, "\"identify_by = nas_identifier\" needs at least one \"nas_identifier\" subsection");
		return -1;
	}

	cn->next = nas_id_clients;
	if (nas_id_clients) nas_id_clients->prev = cn;
	nas_id_clients = cn;
	talloc_set_destructor(cn, client_nas_id_free);

	c->nas_id = cn;
	c->nas_id_only = (!c->secret || !*c->secret);

	/*
	 *	Tools which write the configuration look for this line,
	 *	to tell a server which understands "identify_by" from one
	 *	which ignores it.
	 */
	INFO("client %s: identify_by nas_identifier: %u entries%s", cf_section_name2(cs), cn->count,
	     c->nas_id_only ? "" : ", other packets use the client secret");

	return c->nas_id_only ? 1 : 0;
}

/** Are there identify_by clients at all?
 *
 */
bool client_nas_id_configured(void)
{
	return (nas_id_clients != NULL);
}

/** Find the entry for a NAS-Identifier
 *
 * @param clients the client list of the listener.
 * @param ipaddr source address of the packet.
 * @param value the NAS-Identifier, as in the packet.
 * @param len its length.
 * @return the client of the entry in the identify_by client which covers
 *	ipaddr with the longest prefix, or NULL.
 */
RADCLIENT *client_nas_id_find(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr,
			      uint8_t const *value, size_t len)
{
	nas_id_entry_t	my_entry, *entry, *best = NULL;

	if (!nas_id_tree) return NULL;

	my_entry.value = (char const *) value;
	my_entry.len = len;

	for (entry = rbtree_finddata(nas_id_tree, &my_entry); entry; entry = entry->next) {
		if (!nas_id_usable(entry->parent, clients)) continue;
		if (!nas_id_covers(entry->parent, ipaddr)) continue;
		if (!best || (entry->parent->ipaddr.prefix > best->parent->ipaddr.prefix)) best = entry;
	}

	return best ? best->client : NULL;
}

/** Find the identify_by client which covers an address with the longest prefix
 *
 */
RADCLIENT *client_nas_id_covering(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr)
{
	client_nas_id_t	*cn;
	RADCLIENT	*best = NULL;

	for (cn = nas_id_clients; cn; cn = cn->next) {
		if (!nas_id_usable(cn->parent, clients)) continue;
		if (!nas_id_covers(cn->parent, ipaddr)) continue;
		if (!best || (cn->parent->ipaddr.prefix > best->ipaddr.prefix)) best = cn->parent;
	}

	return best;
}
