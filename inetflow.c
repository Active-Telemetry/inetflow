/* InetFlow - IP Flow Manager
 *
 * Copyright (C) 2021 ECLB Ltd
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>
 */
#include "inetflow.h"

#define DEBUG(fmt, args...)
//#define DEBUG(fmt, args...) {g_printf("%s: ",__func__);g_printf (fmt, ## args);}
#define CHECK_BIT(__v,__p) ((__v) & (1<<(__p)))
#define TIMESTAMP_RESOLUTION_US     1000000
#define FRAG_EXPIRY_TIME            INET_FRAG_DEFAULT_TIMEOUT
#define MAX_FRAG_DEPTH              INET_FRAG_DEFAULT_MAX
#define TCP_FLAGS_MASK              0x01FF
#define MAX_IP_DEPTH                8

/* IP and TCP option kinds that have no length byte */
#define OPT_END                     0
#define OPT_NOP                     1

/* TCP option kinds */
#define TCP_OPT_MSS                 2
#define TCP_OPT_WSCALE              3
#define TCP_OPT_SACK_PERMITTED      4
#define TCP_OPT_SACK                5
#define TCP_OPT_TIMESTAMP           8

/* Flow lifetimes. Each lifetime has its own expiry queue. */
enum {
    LIFETIME_CLOSED,
    LIFETIME_NEW,
    LIFETIME_OPEN,
    LIFETIME_COUNT,
};

static const guint default_timeouts[LIFETIME_COUNT] = {
    INET_FLOW_DEFAULT_CLOSED_TIMEOUT,
    INET_FLOW_DEFAULT_NEW_TIMEOUT,
    INET_FLOW_DEFAULT_OPEN_TIMEOUT,
};

struct _InetTcpFlow;

/* The library allocates an InetFlowPriv for each flow and gives callers a
 * pointer to the public part, which is first */
typedef struct _InetFlowPriv {
    InetFlow pub;
    struct _InetFlowTable *table;
    GList list;                 /* Link in the expiry queue of the lifetime */
    guint8 lifetime;
    guint16 flags;              /* TCP flags of the packet, for lookups */
    guint16 server_port;
    guint32 hash;
    struct _InetTcpFlow *tcp;   /* Created by INET_FLOW_TCP_TRACK */
} InetFlowPriv;

#define FLOW_PRIV(flow) ((InetFlowPriv *) (flow))

#define INET_FRAG_MAX_RANGES 8
typedef struct _InetFragRange {
    guint32 start;
    guint32 end;
} InetFragRange;

typedef struct _InetFragment {
    GList link;                 /* Link in the age queue of the fragment list */
    guint32 hash;
    guint32 id;
    InetTuple tuple;
    guint64 timestamp;
    guint32 offset;             /* Byte offset of the fragment data in the datagram */
    guint32 length;             /* Bytes of data in the fragment */
    guint32 anomalies;          /* INET_ANOMALY_FRAG_ flags for the fragment */
    guint32 total;              /* Datagram length, or zero until the last fragment is seen */
    guint8 nranges;             /* Ranges of the datagram seen so far */
    InetFragRange ranges[INET_FRAG_MAX_RANGES];
} InetFragment;

struct _InetFragList {
    GRWLock lock;
    GHashTable *table;
    GQueue age;                 /* Datagrams in the order they were first seen */
    guint max;
    guint64 timeout_us;
    guint32 seed;               /* Random, so that hash collisions can not be chosen in advance */
};

struct _InetFlowTable {
    GHashTable *table;
    GQueue *expire_queue[LIFETIME_COUNT];
    guint64 timeout_us[LIFETIME_COUNT];
    InetFragList *frag_info_list;
    GDestroyNotify context_free;
    guint64 hits;
    guint64 misses;
    guint64 max;
};

/* Packet */
#define ETH_PROTOCOL_8021Q      0x8100
#define ETH_PROTOCOL_8021AD     0x88A8
#define ETH_PROTOCOL_MPLS_UC    0x8847
#define ETH_PROTOCOL_MPLS_MC    0x8848
#define ETH_PROTOCOL_IP         0x0800
#define ETH_PROTOCOL_IPV6       0x86DD
#define ETH_PROTOCOL_PPPOE_SESS 0x8864

typedef struct ethernet_hdr_t {
    guint8 destination[6];
    guint8 source[6];
    guint16 protocol;
} __attribute__ ((packed)) ethernet_hdr_t;

typedef struct vlan_hdr_t {
    guint16 tci;
    guint16 protocol;
} __attribute__ ((packed)) vlan_hdr_t;

typedef struct pppoe_sess_hdr {
    guint8 ver_type;
    guint8 code;
    guint16 session_id;
    guint16 payload_length;
    guint16 ppp_protocol_id;
} __attribute__ ((packed)) pppoe_sess_hdr_t;

#define GRE_HEADER_CSUM         0x8000
#define GRE_HEADER_ROUTING      0x4000
#define GRE_HEADER_KEY          0x2000
#define GRE_HEADER_SEQ          0x1000

typedef struct gre_hdr_t {
    guint16 flags_version;
    guint16 protocol;
} __attribute__ ((packed)) gre_hdr_t;

#define IP_PROTOCOL_HBH_OPT     0
#define IP_PROTOCOL_ICMP        1
#define IP_PROTOCOL_IPV4        4
#define IP_PROTOCOL_TCP         6
#define IP_PROTOCOL_UDP         17
#define IP_PROTOCOL_IPV6        41
#define IP_PROTOCOL_ROUTING     43
#define IP_PROTOCOL_FRAGMENT    44
#define IP_PROTOCOL_GRE         47
#define IP_PROTOCOL_ESP         50
#define IP_PROTOCOL_AUTH        51
#define IP_PROTOCOL_ICMPV6      58
#define IP_PROTOCOL_NO_NEXT_HDR 59
#define IP_PROTOCOL_DEST_OPT    60
#define IP_PROTOCOL_SCTP        132
#define IP_PROTOCOL_MOBILITY    135
#define IP_PROTOCOL_HIPV2       139
#define IP_PROTOCOL_SHIM6       140

#define IPV6_FIRST_8_OCTETS     1
#define AH_HEADER_LEN_ADD       2
#define FOUR_BYTE_UNITS         4
#define EIGHT_OCTET_UNITS       8

/* PPP protocol IDs */
#define PPP_PROTOCOL_IPV4          0x0021
#define PPP_PROTOCOL_IPV6          0x0057

typedef struct ip_hdr_t {
    guint8 ihl_version;
    guint8 tos;
    guint16 tot_len;
    guint16 id;
    guint16 frag_off;
    guint8 ttl;
    guint8 protocol;
    guint16 check;
    guint32 saddr;
    guint32 daddr;
} __attribute__ ((packed)) ip_hdr_t;

typedef struct ip6_hdr_t {
    guint32 ver_tc_fl;
    guint16 pay_len;
    guint8 next_hdr;
    guint8 hop_limit;
    guint8 saddr[16];
    guint8 daddr[16];
} __attribute__ ((packed)) ip6_hdr_t;

typedef struct tcp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 seq;
    guint32 ack;
    guint16 flags;
    guint16 window;
    guint16 check;
    guint16 urg_ptr;
} __attribute__ ((packed)) tcp_hdr_t;

typedef struct udp_hdr_t {
    guint16 source;
    guint16 destination;
    guint16 length;
    guint16 check;
} __attribute__ ((packed)) udp_hdr_t;

typedef struct frag_hdr_t {
    guint8 next_hdr;
    guint8 res;
    guint16 fo_res_mflag;
    guint32 id;
} __attribute__ ((packed)) frag_hdr_t;

typedef struct auth_hdr_t {
    guint8 next_hdr;
    guint8 payload_len;
    guint16 reserved;
    guint64 spi_seq;
    guint64 icv;
} __attribute__ ((packed)) auth_hdr_t;

typedef struct sctp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 ver_tag;
    guint32 checksum;
} __attribute__ ((packed)) sctp_hdr_t;

typedef struct ipv6_partial_ext_hdr_t {
    guint8 next_hdr;
    guint8 hdr_ext_len;
} __attribute__ ((packed)) ipv6_partial_ext_hdr_t;

static gboolean flow_parse_ipv4(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags,
                                guint depth);
static gboolean flow_parse_ipv6(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags,
                                guint depth);

struct _InetTcpFlow;
static void tcp_flow_free(struct _InetTcpFlow *tcp_flow);

static inline guint64 get_time_us(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        return (now.tv_sec * (guint64) TIMESTAMP_RESOLUTION_US + (now.tv_nsec / 1000));
    else
        return 0;
}

static int addr_compare(const InetTuple * tuple, const InetAddr * a, const InetAddr * b)
{
    return memcmp(a, b, tuple->family == AF_INET ? sizeof(a->v4) : sizeof(a->v6));
}

void inet_tuple_set(InetTuple * tuple, guint8 family, guint8 protocol, const void *src, guint16 sport, const void *dst, guint16 dport)
{
    size_t len = family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

    memset(tuple, 0, sizeof(*tuple));
    tuple->family = family;
    tuple->protocol = protocol;
    memcpy(&tuple->src, src, len);
    memcpy(&tuple->dst, dst, len);
    tuple->sport = sport;
    tuple->dport = dport;
}

static gboolean tuple_src_is_server(const InetTuple * tuple)
{
    guint16 sport = GUINT16_FROM_BE(tuple->sport);
    guint16 dport = GUINT16_FROM_BE(tuple->dport);

    return sport < dport || (sport == dport && addr_compare(tuple, &tuple->src, &tuple->dst) < 0);
}

const InetAddr *inet_tuple_server_addr(const InetTuple * tuple)
{
    return tuple_src_is_server(tuple) ? &tuple->src : &tuple->dst;
}

guint16 inet_tuple_server_port(const InetTuple * tuple)
{
    return tuple_src_is_server(tuple) ? tuple->sport : tuple->dport;
}

const InetAddr *inet_tuple_client_addr(const InetTuple * tuple)
{
    return tuple_src_is_server(tuple) ? &tuple->dst : &tuple->src;
}

guint16 inet_tuple_client_port(const InetTuple * tuple)
{
    return tuple_src_is_server(tuple) ? tuple->dport : tuple->sport;
}

void inet_tuple_to_sockaddr(const InetTuple * tuple, gboolean src, struct sockaddr_storage *out)
{
    const InetAddr *addr = src ? &tuple->src : &tuple->dst;
    guint16 port = src ? tuple->sport : tuple->dport;

    memset(out, 0, sizeof(*out));
    if (tuple->family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_addr = addr->v4;
        sin->sin_port = port;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = addr->v6;
        sin6->sin6_port = port;
    }
}

gboolean inet_tuple_equal(const InetTuple * a, const InetTuple * b)
{
    if (a->protocol != b->protocol || a->family != b->family) {
        return FALSE;
    }
    /* The two directions of a flow have the same tuple, or the same tuple
     * with its ends swapped, so the server ends need not be found */
    if (a->sport == b->sport && a->dport == b->dport && addr_compare(a, &a->src, &b->src) == 0 && addr_compare(a, &a->dst, &b->dst) == 0)
        return TRUE;
    return a->sport == b->dport && a->dport == b->sport && addr_compare(a, &a->src, &b->dst) == 0 && addr_compare(a, &a->dst, &b->src) == 0;
}

gboolean inet_tuple_exact(const InetTuple * a, const InetTuple * b)
{
    if (a->protocol != b->protocol || a->family != b->family) {
        return FALSE;
    }
    return addr_compare(a, &a->src, &b->src) == 0 && a->sport == b->sport && addr_compare(a, &a->dst, &b->dst) == 0 && a->dport == b->dport;
}

/* Odd 64-bit multipliers, chosen at random once for each process, so that
 * hash collisions can not be chosen in advance. inet_tuple_hash() and every
 * flow table must give a tuple the same hash, so the multipliers belong to
 * the process and not to a table. */
#define HASH_KEYS 5
static guint64 hash_keys[HASH_KEYS];
static gsize hash_keys_set;

/* The multipliers can be chosen once, before any flow is hashed. A table
 * keeps the hashes of its flows, so other multipliers would not find them. */
static gboolean hash_keys_from_seed(guint64 seed)
{
    int i;

    if (!g_once_init_enter(&hash_keys_set))
        return FALSE;
    /* splitmix64 gives well mixed multipliers from any seed, including 0 */
    for (i = 0; i < HASH_KEYS; i++) {
        guint64 z = (seed += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        hash_keys[i] = (z ^ (z >> 31)) | 1;
    }
    g_once_init_leave(&hash_keys_set, 1);
    return TRUE;
}

static void hash_keys_init(void)
{
    if (!g_atomic_pointer_get(&hash_keys_set))
        hash_keys_from_seed((guint64) g_random_int() << 32 | g_random_int());
}

gboolean inet_flow_hash_seed_set(guint64 seed)
{
    return hash_keys_from_seed(seed);
}

/* Multiply each pair of words by its own random multiplier and sum the
 * products. The high half of the sum depends on every bit of the words.
 * This costs two multiplications for an IPv4 tuple. */
static guint32 hash_words(const guint32 * k, guint n, guint32 seed)
{
    guint64 h = (guint64) seed << 32 | seed;
    guint i;

    hash_keys_init();
    for (i = 0; i + 1 < n; i += 2)
        h += ((guint64) k[i] | (guint64) k[i + 1] << 32) * hash_keys[i / 2];
    if (n & 1)
        h += (guint64) k[n - 1] * hash_keys[n / 2];
    return h >> 32;
}

/* Hash the server end before the client end, so that both directions of a
 * flow have the same hash. The words are in host byte order and the family
 * is the IP version, so a seeded hash is the same on every CPU and system. */
static guint32 tuple_hash(const InetTuple * tuple)
{
    gboolean src_is_server = tuple_src_is_server(tuple);
    const InetAddr *server = src_is_server ? &tuple->src : &tuple->dst;
    const InetAddr *client = src_is_server ? &tuple->dst : &tuple->src;
    guint16 server_port = src_is_server ? tuple->sport : tuple->dport;
    guint16 client_port = src_is_server ? tuple->dport : tuple->sport;
    guint addr_words = tuple->family == AF_INET ? 1 : 4;
    guint32 words[10];
    guint n = 0;
    guint i;

    for (i = 0; i < addr_words; i++)
        words[n++] = GUINT32_FROM_BE(((const guint32 *)server)[i]);
    for (i = 0; i < addr_words; i++)
        words[n++] = GUINT32_FROM_BE(((const guint32 *)client)[i]);
    words[n++] = (guint32) GUINT16_FROM_BE(server_port) << 16 | GUINT16_FROM_BE(client_port);
    words[n++] = (guint32) (tuple->family == AF_INET ? 4 : 6) << 8 | tuple->protocol;
    return hash_words(words, n, 0);
}

/* The flow tables use this hash, and keep it in the tuple of each packet and
 * flow, so for those tuples this returns the stored value */
guint inet_tuple_hash(InetTuple * tuple)
{
    if (!tuple->hash)
        tuple->hash = tuple_hash(tuple);
    return tuple->hash;
}

/* A datagram is identified by its source, destination, protocol and ID, so a
 * fragment in the other direction belongs to another datagram. The ports are
 * not in non-first fragments, so they are not part of the key. */
static guint32 frag_hash(const InetFragment * f, guint32 seed)
{
    guint32 words[10];
    guint addr_words = f->tuple.family == AF_INET ? 1 : 4;
    guint n = 0;

    memcpy(&words[n], &f->tuple.src, addr_words * sizeof(guint32));
    n += addr_words;
    memcpy(&words[n], &f->tuple.dst, addr_words * sizeof(guint32));
    n += addr_words;
    words[n++] = f->id;
    words[n++] = (guint32) f->tuple.family << 8 | f->tuple.protocol;
    return hash_words(words, n, seed);
}

static guint frag_hash_get(gconstpointer f)
{
    return ((const InetFragment *)f)->hash;
}

static gboolean frag_equal(gconstpointer a, gconstpointer b)
{
    const InetFragment *x = a;
    const InetFragment *y = b;

    return x->id == y->id && x->tuple.protocol == y->tuple.protocol && x->tuple.family == y->tuple.family
        && addr_compare(&x->tuple, &x->tuple.src, &y->tuple.src) == 0 && addr_compare(&x->tuple, &x->tuple.dst, &y->tuple.dst) == 0;
}

static gboolean frag_is_expired(InetFragList * list, InetFragment * frag_info, guint64 timestamp)
{
    /* Caller supplied timestamps can go backwards, which is not expiry */
    if (timestamp > frag_info->timestamp && timestamp - frag_info->timestamp > list->timeout_us)
        return TRUE;
    return FALSE;
}

static void frag_remove(InetFragList * list, InetFragment * frag)
{
    g_hash_table_remove(list->table, frag);
    g_queue_unlink(&list->age, &frag->link);
    g_free(frag);
}

/* A datagram keeps the timestamp of its first fragment, so the age queue is in
 * expiry order and the expired datagrams are at its head */
static guint clear_expired_frag_info(InetFragList * list, guint64 timestamp)
{
    guint cleared = 0;

    while (list->age.head && frag_is_expired(list, list->age.head->data, timestamp)) {
        frag_remove(list, list->age.head->data);
        cleared++;
    }
    return cleared;
}

/* Add the range of a fragment to the ranges seen for its datagram. Ranges that
 * touch are merged, so a datagram received in order uses one range. */
static void add_frag_range(InetFragment * found, guint32 start, guint32 end)
{
    int i;

    for (i = 0; i < found->nranges; i++) {
        InetFragRange *r = &found->ranges[i];
        if (r->start <= end && start <= r->end) {
            start = MIN(start, r->start);
            end = MAX(end, r->end);
            found->ranges[i--] = found->ranges[--found->nranges];
        }
    }
    /* With too many separate ranges the datagram can not complete and expires */
    if (found->nranges < INET_FRAG_MAX_RANGES) {
        found->ranges[found->nranges].start = start;
        found->ranges[found->nranges].end = end;
        found->nranges++;
    }
}

static gboolean frag_overlaps(InetFragment * found, guint32 start, guint32 end)
{
    int i;

    for (i = 0; i < found->nranges; i++) {
        if (start < found->ranges[i].end && found->ranges[i].start < end)
            return TRUE;
    }
    return FALSE;
}

static gboolean store_frag_info(InetFragList * fragments, InetFragment * f, guint64 timestamp)
{
    InetFragment *entry;

    if (g_hash_table_size(fragments->table) >= fragments->max && clear_expired_frag_info(fragments, timestamp) == 0) {
        DEBUG("Fragment tracking limit reached\n");
        f->anomalies |= INET_ANOMALY_FRAG_LIMIT;
        return FALSE;
    }
    entry = g_malloc0(sizeof(InetFragment));
    entry->link.data = entry;
    entry->hash = f->hash;
    entry->id = f->id;
    entry->tuple = f->tuple;
    entry->timestamp = timestamp;
    entry->total = f->total;
    add_frag_range(entry, f->offset, f->offset + f->length);
    g_queue_push_tail_link(&fragments->age, &entry->link);
    g_hash_table_add(fragments->table, entry);
    return TRUE;
}

/* Match a fragment to its datagram. The entry gives the fragment offset and
 * length, and returns the ports and the anomalies. Returns FALSE when the
 * datagram can not be tracked. */
static gboolean frag_list_update(InetFragList * fragments, InetFragment * entry, gboolean more_fragments)
{
    guint32 start = entry->offset;
    guint32 end = entry->offset + entry->length;
    guint64 timestamp = entry->timestamp ? : get_time_us();
    InetFragment *found;
    gboolean result;

    entry->anomalies = 0;
    entry->total = more_fragments ? 0 : end;
    entry->hash = frag_hash(entry, fragments->seed);

    g_rw_lock_writer_lock(&fragments->lock);
    found = g_hash_table_lookup(fragments->table, entry);
    if (found && frag_is_expired(fragments, found, timestamp)) {
        entry->anomalies |= INET_ANOMALY_FRAG_EXPIRED;
        frag_remove(fragments, found);
        found = NULL;
    }

    if (!found) {
        result = store_frag_info(fragments, entry, timestamp);
        g_rw_lock_writer_unlock(&fragments->lock);
        return result;
    }

    if (frag_overlaps(found, start, end))
        entry->anomalies |= INET_ANOMALY_FRAG_OVERLAP;
    add_frag_range(found, start, end);
    if (!more_fragments)
        found->total = end;

    /* The first fragment holds the ports. It can arrive after other fragments,
     * so store its ports, or give the stored ports to a later fragment. */
    if (start == 0) {
        found->tuple.sport = entry->tuple.sport;
        found->tuple.dport = entry->tuple.dport;
    } else {
        entry->tuple.sport = found->tuple.sport;
        entry->tuple.dport = found->tuple.dport;
    }

    /* Stop tracking the datagram once all of its data has been seen */
    if (found->total && found->nranges == 1 && found->ranges[0].start == 0 && found->ranges[0].end >= found->total)
        frag_remove(fragments, found);
    g_rw_lock_writer_unlock(&fragments->lock);
    return TRUE;
}

void inet_frag_list_free(InetFragList * fragments)
{
    g_rw_lock_writer_lock(&fragments->lock);
    while (fragments->age.head)
        frag_remove(fragments, fragments->age.head->data);
    g_hash_table_destroy(fragments->table);
    g_rw_lock_writer_unlock(&fragments->lock);
    g_rw_lock_clear(&fragments->lock);
    g_free(fragments);
}

static void frag_list_limits_set(InetFragList * fragments, guint max_datagrams, guint timeout_s)
{
    fragments->max = max_datagrams;
    fragments->timeout_us = (guint64) timeout_s *TIMESTAMP_RESOLUTION_US;
}

InetFragList *inet_frag_list_new(guint max_datagrams, guint timeout_s)
{
    InetFragList *new_list = g_malloc0(sizeof(InetFragList));

    g_rw_lock_init(&new_list->lock);
    new_list->table = g_hash_table_new(frag_hash_get, frag_equal);
    g_queue_init(&new_list->age);
    new_list->seed = g_random_int();
    frag_list_limits_set(new_list, max_datagrams, timeout_s);
    return new_list;
}

static guint32 get_hdr_len(guint8 hdr_ext_len)
{
    return (hdr_ext_len + IPV6_FIRST_8_OCTETS) * EIGHT_OCTET_UNITS;
}

static guint32 flow_hash(InetFlowPriv * f)
{
    if (!f->hash)
        f->hash = inet_tuple_hash(&f->pub.tuple);
    return f->hash;
}

static gboolean flow_compare(InetFlowPriv * f1, InetFlowPriv * f2)
{
    return inet_tuple_equal(&f1->pub.tuple, &f2->pub.tuple);
}

static inline void set_anomaly(InetPacket * pkt, guint32 anomaly)
{
    pkt->anomalies |= anomaly;
}

/* Each tunnel level is parsed by recursion, so a frame of nested headers
 * would otherwise use stack in proportion to its length */
static gboolean ip_depth_ok(InetPacket * pkt, guint depth)
{
    if (depth < MAX_IP_DEPTH)
        return TRUE;
    set_anomaly(pkt, INET_ANOMALY_TUNNEL_DEPTH);
    return FALSE;
}

static void set_payload(InetPacket * pkt, const guint8 * data, guint32 length, guint32 hdr_len)
{
    if (hdr_len <= length) {
        pkt->payload = data + hdr_len;
        pkt->payload_length = length - hdr_len;
    }
}

/* Walk a list of IP or TCP options and return FALSE if one has an invalid
 * length. Call func for each option that has a length byte. */
typedef void (*OptFunc) (guint8 kind, const guint8 * opt, guint8 len, InetPacket * pkt);
static gboolean parse_options(const guint8 * opts, guint32 length, OptFunc func, InetPacket * pkt)
{
    guint32 i = 0;

    while (i < length) {
        guint8 kind = opts[i];
        if (kind == OPT_END)
            break;
        if (kind == OPT_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= length || opts[i + 1] < 2 || i + opts[i + 1] > length)
            return FALSE;
        if (func)
            func(kind, opts + i, opts[i + 1], pkt);
        i += opts[i + 1];
    }
    return TRUE;
}

static void tcp_option(guint8 kind, const guint8 * opt, guint8 len, InetPacket * pkt)
{
    guint8 flag;
    guint8 valid_len;

    switch (kind) {
    case TCP_OPT_MSS:
        flag = INET_TCP_OPT_MSS;
        valid_len = 4;
        break;
    case TCP_OPT_WSCALE:
        flag = INET_TCP_OPT_WSCALE;
        valid_len = 3;
        break;
    case TCP_OPT_SACK_PERMITTED:
        flag = INET_TCP_OPT_SACK_PERMITTED;
        valid_len = 2;
        break;
    case TCP_OPT_TIMESTAMP:
        flag = INET_TCP_OPT_TIMESTAMP;
        valid_len = 10;
        break;
    case TCP_OPT_SACK:
        /* A SACK option holds one to four blocks of eight bytes */
        if (len < 10 || len > 34 || (len - 2) % 8)
            set_anomaly(pkt, INET_ANOMALY_TCP_OPT_INVALID);
        else
            pkt->tcp.options |= INET_TCP_OPT_SACK;
        return;
    default:
        return;
    }

    if (len != valid_len) {
        set_anomaly(pkt, INET_ANOMALY_TCP_OPT_INVALID);
        return;
    }
    if (pkt->tcp.options & flag) {
        set_anomaly(pkt, INET_ANOMALY_TCP_OPT_DUPLICATE);
        return;
    }
    pkt->tcp.options |= flag;
    switch (kind) {
    case TCP_OPT_MSS:
        pkt->tcp.mss = (opt[2] << 8) | opt[3];
        break;
    case TCP_OPT_WSCALE:
        pkt->tcp.wscale = opt[2];
        break;
    case TCP_OPT_TIMESTAMP:
        /* Options are not aligned, so copy the values out */
        memcpy(&pkt->tcp.ts_val, opt + 2, sizeof(pkt->tcp.ts_val));
        memcpy(&pkt->tcp.ts_ecr, opt + 6, sizeof(pkt->tcp.ts_ecr));
        pkt->tcp.ts_val = GUINT32_FROM_BE(pkt->tcp.ts_val);
        pkt->tcp.ts_ecr = GUINT32_FROM_BE(pkt->tcp.ts_ecr);
        break;
    }
}

static gboolean flow_parse_tcp(InetPacket * pkt, const guint8 * data, guint32 length, guint32 flags)
{
    tcp_hdr_t *tcp = (tcp_hdr_t *) data;
    guint16 offset_flags;
    guint32 hdr_len;

    if (length < sizeof(tcp_hdr_t)) {
        set_anomaly(pkt, INET_ANOMALY_TCP_TRUNCATED);
        return FALSE;
    }

    pkt->tuple.sport = tcp->source;
    pkt->tuple.dport = tcp->destination;
    offset_flags = GUINT16_FROM_BE(tcp->flags);
    hdr_len = (offset_flags >> 12) * FOUR_BYTE_UNITS;
    pkt->tcp.flags = offset_flags & TCP_FLAGS_MASK;
    pkt->tcp.seq = GUINT32_FROM_BE(tcp->seq);
    pkt->tcp.ack = GUINT32_FROM_BE(tcp->ack);
    pkt->tcp.window = GUINT16_FROM_BE(tcp->window);
    if (hdr_len < sizeof(tcp_hdr_t))
        set_anomaly(pkt, INET_ANOMALY_TCP_HLEN_TOO_SMALL);
    else if (hdr_len > length)
        set_anomaly(pkt, INET_ANOMALY_TCP_TRUNCATED);
    else {
        set_payload(pkt, data, length, hdr_len);
        if ((flags & (INET_FLOW_VALIDATE | INET_FLOW_TCP_TRACK))
            && !parse_options(data + sizeof(tcp_hdr_t), hdr_len - sizeof(tcp_hdr_t), tcp_option, pkt))
            set_anomaly(pkt, INET_ANOMALY_TCP_OPT_INVALID);
    }
    return TRUE;
}

static gboolean flow_parse_udp(InetPacket * pkt, const guint8 * data, guint32 length)
{
    udp_hdr_t *udp = (udp_hdr_t *) data;
    if (length < sizeof(udp_hdr_t)) {
        set_anomaly(pkt, INET_ANOMALY_UDP_TRUNCATED);
        return FALSE;
    }
    /* The UDP length covers the whole datagram, which a fragment does not hold */
    if (GUINT16_FROM_BE(udp->length) < sizeof(udp_hdr_t) || (!pkt->fragment && GUINT16_FROM_BE(udp->length) > length))
        set_anomaly(pkt, INET_ANOMALY_UDP_LEN_INVALID);

    pkt->tuple.sport = udp->source;
    pkt->tuple.dport = udp->destination;
    set_payload(pkt, data, length, sizeof(udp_hdr_t));
    return TRUE;
}

static gboolean flow_parse_sctp(InetPacket * pkt, const guint8 * data, guint32 length)
{
    sctp_hdr_t *sctp = (sctp_hdr_t *) data;
    if (length < sizeof(sctp_hdr_t))
        return FALSE;

    pkt->tuple.sport = sctp->source;
    pkt->tuple.dport = sctp->destination;
    set_payload(pkt, data, length, sizeof(sctp_hdr_t));
    return TRUE;
}

/* Record the IP header and the transport header, which is NULL for non-first
 * fragments. Tunnelled packets record the inner headers because the inner
 * parse runs last. */
static void set_headers(InetPacket * pkt, const guint8 * l3, const guint8 * l4)
{
    pkt->l3 = l3;
    pkt->l4 = l4;
    pkt->payload = NULL;
    pkt->payload_length = 0;
    pkt->tcp.options = 0;
}

static gboolean flow_parse_gre(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags,
                               guint depth)
{
    gre_hdr_t *gre = (gre_hdr_t *) data;
    if (length < sizeof(gre_hdr_t))
        return FALSE;
    int offset = sizeof(gre_hdr_t);
    guint16 gre_flags = GUINT16_FROM_BE(gre->flags_version);
    guint16 proto = GUINT16_FROM_BE(gre->protocol);

    if (gre_flags & (GRE_HEADER_CSUM | GRE_HEADER_ROUTING))
        offset += 4;
    if (gre_flags & GRE_HEADER_KEY)
        offset += 4;
    if (gre_flags & GRE_HEADER_SEQ)
        offset += 4;
    if (length < offset)
        return FALSE;

    DEBUG("Protocol: %d\n", proto);
    switch (proto) {
    case ETH_PROTOCOL_IP:
        if (!flow_parse_ipv4(pkt, data + offset, length - offset, fragments, ts, flags, depth + 1))
            return FALSE;
        break;
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ipv6(pkt, data + offset, length - offset, fragments, ts, flags, depth + 1))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

static gboolean flow_parse_ipv4(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags,
                                guint depth)
{
    InetTuple *f = &pkt->tuple;
    ip_hdr_t *iph = (ip_hdr_t *) data;
    guint32 hdr_len;
    guint16 tot_len;

    if (!ip_depth_ok(pkt, depth))
        return FALSE;
    if (length < sizeof(ip_hdr_t)) {
        set_anomaly(pkt, INET_ANOMALY_IPV4_TRUNCATED);
        return FALSE;
    }
    hdr_len = (iph->ihl_version & 0x0f) * FOUR_BYTE_UNITS;
    if (hdr_len < sizeof(ip_hdr_t)) {
        set_anomaly(pkt, INET_ANOMALY_IPV4_HLEN_TOO_SMALL);
        return FALSE;
    }
    if (length < hdr_len) {
        set_anomaly(pkt, INET_ANOMALY_IPV4_TRUNCATED);
        return FALSE;
    }
    if ((flags & INET_FLOW_VALIDATE)
        && !parse_options(data + sizeof(ip_hdr_t), hdr_len - sizeof(ip_hdr_t), NULL, pkt))
        set_anomaly(pkt, INET_ANOMALY_IPV4_OPT_INVALID);
    tot_len = GUINT16_FROM_BE(iph->tot_len);
    if (tot_len < hdr_len)
        set_anomaly(pkt, INET_ANOMALY_IPV4_LEN_TOO_SMALL);
    else if (tot_len > length)
        set_anomaly(pkt, INET_ANOMALY_IPV4_TRUNCATED);
    else
        /* Ignore link layer padding after the end of the IP packet */
        length = tot_len;
    set_headers(pkt, data, (GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) == 0 ? data + hdr_len : NULL);
    pkt->fragment = (GUINT16_FROM_BE(iph->frag_off) & 0x3FFF) != 0;

    f->family = AF_INET;
    memset(&f->src, 0, sizeof(f->src));
    memset(&f->dst, 0, sizeof(f->dst));
    memcpy(&f->src.v4, &iph->saddr, sizeof(f->src.v4));
    memcpy(&f->dst.v4, &iph->daddr, sizeof(f->dst.v4));

    DEBUG("Protocol: %d\n", iph->protocol);
    inet_tuple_set_protocol(f, iph->protocol);

    f->offset += hdr_len;
    /* Don't bother with this for non-first fragments */
    if ((GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) == 0) {
        switch (iph->protocol) {
        case IP_PROTOCOL_TCP:
            if (!flow_parse_tcp(pkt, data + hdr_len, length - hdr_len, flags))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp(pkt, data + hdr_len, length - hdr_len))
                return FALSE;
            break;
        case IP_PROTOCOL_SCTP:
            if (!flow_parse_sctp(pkt, data + hdr_len, length - hdr_len))
                return FALSE;
            break;
        case IP_PROTOCOL_IPV4:
            if (flags & INET_FLOW_TUNNEL) {
                if (!flow_parse_ipv4(pkt, data + hdr_len, length - hdr_len, fragments, ts, flags, depth + 1))
                    return FALSE;
            }
            break;
        case IP_PROTOCOL_IPV6:
            if (flags & INET_FLOW_TUNNEL) {
                if (!flow_parse_ipv6(pkt, data + hdr_len, length - hdr_len, fragments, ts, flags, depth + 1))
                    return FALSE;
            }
            break;
        case IP_PROTOCOL_GRE:
            if (flags & INET_FLOW_TUNNEL) {
                if (!flow_parse_gre(pkt, data + hdr_len, length - hdr_len, fragments, ts, flags, depth))
                    return FALSE;
            }
            break;
        case IP_PROTOCOL_ICMP:
        default:
            f->sport = 0;
            f->dport = 0;
            break;
        }
    }

    /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
     * to find sport and dport. First fragments need to be saved.
     */
    if (GUINT16_FROM_BE(iph->frag_off) & 0x3FFF) {
        InetFragment entry = { 0 };
        entry.id = iph->id;
        entry.tuple = *f;
        entry.timestamp = ts;
        entry.offset = (GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) * EIGHT_OCTET_UNITS;
        entry.length = length - hdr_len;

        if (hdr_len + entry.offset + entry.length > G_MAXUINT16)
            set_anomaly(pkt, INET_ANOMALY_FRAG_TOO_LARGE);
        if (!fragments)
            return TRUE;

        gboolean more_fragments = ! !(GUINT16_FROM_BE(iph->frag_off) & 0x2000);

        gboolean result = frag_list_update(fragments, &entry, more_fragments);
        set_anomaly(pkt, entry.anomalies);
        *f = entry.tuple;
        if (!result)
            pkt->status = INET_PACKET_FRAG_UNTRACKED;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ipv6(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags,
                                guint depth)
{
    InetTuple *f = &pkt->tuple;
    ip6_hdr_t *iph = (ip6_hdr_t *) data;
    frag_hdr_t *fragment_hdr = NULL;
    guint32 frag_length = 0;
    auth_hdr_t *auth_hdr;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr;

    if (!ip_depth_ok(pkt, depth))
        return FALSE;
    if (length < sizeof(ip6_hdr_t)) {
        set_anomaly(pkt, INET_ANOMALY_IPV6_TRUNCATED);
        return FALSE;
    }
    /* Ignore link layer padding after the end of the IP packet. A payload
     * length of zero means a jumbogram, where the length is in an option. */
    if (iph->pay_len) {
        if (sizeof(ip6_hdr_t) + GUINT16_FROM_BE(iph->pay_len) > length)
            set_anomaly(pkt, INET_ANOMALY_IPV6_TRUNCATED);
        else
            length = sizeof(ip6_hdr_t) + GUINT16_FROM_BE(iph->pay_len);
    }
    set_headers(pkt, data, NULL);
    pkt->fragment = FALSE;

    f->family = AF_INET6;
    memcpy(&f->src.v6, iph->saddr, sizeof(f->src.v6));
    memcpy(&f->dst.v6, iph->daddr, sizeof(f->dst.v6));
    inet_tuple_set_protocol(f, iph->next_hdr);

    data += sizeof(ip6_hdr_t);
    length -= sizeof(ip6_hdr_t);
    f->offset += sizeof(ip6_hdr_t);

  next_header:
    DEBUG("Next Header: %u\n", inet_tuple_get_protocol(f));
    pkt->l4 = data;
    switch (inet_tuple_get_protocol(f)) {
    case IP_PROTOCOL_TCP:
        if (!flow_parse_tcp(pkt, data, length, flags)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_UDP:
        if (!flow_parse_udp(pkt, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_SCTP:
        if (!flow_parse_sctp(pkt, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_IPV4:
        if (flags & INET_FLOW_TUNNEL)
            if (!flow_parse_ipv4(pkt, data, length, fragments, ts, flags, depth + 1)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_IPV6:
        if (flags & INET_FLOW_TUNNEL)
            if (!flow_parse_ipv6(pkt, data, length, fragments, ts, flags, depth + 1)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_GRE:
        if (flags & INET_FLOW_TUNNEL)
            if (!flow_parse_gre(pkt, data, length, fragments, ts, flags, depth)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        if (length < sizeof(ipv6_partial_ext_hdr_t)
            || length < get_hdr_len(((ipv6_partial_ext_hdr_t *) data)->hdr_ext_len)) {
            set_anomaly(pkt, INET_ANOMALY_IPV6_EXTHDR_TRUNCATED);
            return FALSE;
        }
        ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) data;
        inet_tuple_set_protocol(f, ipv6_part_hdr->next_hdr);
        data += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        length -= get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        goto next_header;
    case IP_PROTOCOL_FRAGMENT:
        if (length < sizeof(frag_hdr_t)) {
            set_anomaly(pkt, INET_ANOMALY_IPV6_EXTHDR_TRUNCATED);
            return FALSE;
        }
        inet_tuple_set_protocol(f, ((frag_hdr_t *) data)->next_hdr);
        /* An atomic fragment, with offset 0 and no more fragments, holds a
         * whole datagram. RFC 6946 requires it to be processed apart from
         * other fragments with the same ID, so it is not tracked. */
        if (!(GUINT16_FROM_BE(((frag_hdr_t *) data)->fo_res_mflag) & 0xFFF9)) {
            data += sizeof(frag_hdr_t);
            length -= sizeof(frag_hdr_t);
            goto next_header;
        }
        fragment_hdr = (frag_hdr_t *) data;
        pkt->fragment = TRUE;

        data += sizeof(frag_hdr_t);
        length -= sizeof(frag_hdr_t);
        frag_length = length;

        /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
         * to find sport and dport - there's no point continuing to parse.
         */
        if ((GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0xFFF8)) {
            pkt->l4 = NULL;
            break;
        }

        goto next_header;
    case IP_PROTOCOL_AUTH:
        if (length < sizeof(auth_hdr_t)
            || length < (((auth_hdr_t *) data)->payload_len + AH_HEADER_LEN_ADD)
            * FOUR_BYTE_UNITS) {
            set_anomaly(pkt, INET_ANOMALY_IPV6_EXTHDR_TRUNCATED);
            return FALSE;
        }
        auth_hdr = (auth_hdr_t *) data;
        inet_tuple_set_protocol(f, auth_hdr->next_hdr);
        data += (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
        length -= (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
        goto next_header;
    case IP_PROTOCOL_ESP:
    case IP_PROTOCOL_NO_NEXT_HDR:
    case IP_PROTOCOL_ICMPV6:
    default:
        break;
    }

    /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
     * to find sport and dport. First IP fragments need to be added to the list.
     */
    if (fragment_hdr) {
        InetFragment entry = { 0 };
        entry.id = fragment_hdr->id;
        entry.tuple = *f;
        entry.timestamp = ts;
        entry.offset = GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0xFFF8;
        entry.length = frag_length;

        if (entry.offset + entry.length > G_MAXUINT16)
            set_anomaly(pkt, INET_ANOMALY_FRAG_TOO_LARGE);
        if (!fragments)
            return TRUE;

        gboolean more_fragments = ! !(GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0x1);

        gboolean result = frag_list_update(fragments, &entry, more_fragments);
        set_anomaly(pkt, entry.anomalies);
        *f = entry.tuple;
        if (!result)
            pkt->status = INET_PACKET_FRAG_UNTRACKED;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ip(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags)
{
    guint8 version;

    if (length < sizeof(version))
        return FALSE;

    version = *data;
    version = 0x0f & (version >> 4);

    if (version == 4) {
        if (!flow_parse_ipv4(pkt, data, length, fragments, ts, flags, 0))
            return FALSE;
    } else if (version == 6) {
        if (!flow_parse_ipv6(pkt, data, length, fragments, ts, flags, 0))
            return FALSE;
    } else {
        DEBUG("Unsupported ip version: %d\n", version);
        set_anomaly(pkt, INET_ANOMALY_IP_VERSION);
        return FALSE;
    }
    return TRUE;
}

static gboolean flow_parse(InetPacket * pkt, const guint8 * data, guint32 length, InetFragList * fragments, guint64 ts, guint32 flags)
{
    InetTuple *f = pkt ? &pkt->tuple : NULL;
    ethernet_hdr_t *e;
    vlan_hdr_t *v;
    pppoe_sess_hdr_t *pppoe;
    guint32 label;
    int labels = 0;
    guint16 type;
    int tags = 0;

    if (!f || !data || !length) {
        DEBUG("Invalid parameters: f:%p data:%p length:%u\n", f, data, length);
        return FALSE;
    }

    if (length < sizeof(ethernet_hdr_t)) {
        DEBUG("Frame too short: %u\n", length);
        return FALSE;
    }

    e = (ethernet_hdr_t *) data;
    data += sizeof(ethernet_hdr_t);
    length -= sizeof(ethernet_hdr_t);
    f->offset += sizeof(ethernet_hdr_t);
    type = GUINT16_FROM_BE(e->protocol);
  try_again:
    switch (type) {
    case ETH_PROTOCOL_8021Q:
    case ETH_PROTOCOL_8021AD:
        tags++;
        if (tags > 2)
            return FALSE;
        if (length < sizeof(vlan_hdr_t))
            return FALSE;
        v = (vlan_hdr_t *) data;
        type = GUINT16_FROM_BE(v->protocol);
        data += sizeof(vlan_hdr_t);
        length -= sizeof(vlan_hdr_t);
        f->offset += sizeof(vlan_hdr_t);
        goto try_again;
    case ETH_PROTOCOL_MPLS_UC:
    case ETH_PROTOCOL_MPLS_MC:
        labels++;
        if (labels > 3)
            return FALSE;
        if (length < sizeof(guint32))
            return FALSE;
        label = GUINT32_FROM_BE(*((guint32 *) data));
        data += sizeof(guint32);
        length -= sizeof(guint32);
        f->offset += sizeof(guint32);
        if ((label & 0x100) != 0x100)
            type = ETH_PROTOCOL_MPLS_UC;
        else
            type = ETH_PROTOCOL_IP;
        goto try_again;
    case ETH_PROTOCOL_IP:
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ip(pkt, data, length, fragments, ts, flags))
            return FALSE;
        break;
    case ETH_PROTOCOL_PPPOE_SESS:
        if (length < sizeof(pppoe_sess_hdr_t))
            return FALSE;
        pppoe = (pppoe_sess_hdr_t *) data;
        if (pppoe->ppp_protocol_id == g_htons(PPP_PROTOCOL_IPV4)) {
            type = ETH_PROTOCOL_IP;
        } else if (pppoe->ppp_protocol_id == g_htons(PPP_PROTOCOL_IPV6)) {
            type = ETH_PROTOCOL_IPV6;
        } else {
            DEBUG("Unsupported PPPOE protocol: 0x%04x\n", g_ntohs(pppoe->ppp_protocol_id));
            return FALSE;
        }
        data += sizeof(pppoe_sess_hdr_t);
        length -= sizeof(pppoe_sess_hdr_t);
        f->offset += sizeof(pppoe_sess_hdr_t);
        goto try_again;
    default:
        DEBUG("Unsupported ethernet protocol: 0x%04x\n", type);
        return FALSE;
    }
    return TRUE;
}


static void remove_flow_by_expiry(InetFlowPriv * flow)
{
    g_queue_unlink(flow->table->expire_queue[flow->lifetime], &flow->list);
}

static void insert_flow_by_expiry(InetFlowPriv * flow)
{
    g_queue_push_tail_link(flow->table->expire_queue[flow->lifetime], &flow->list);
}

static void flow_lifetime_set(InetFlowPriv * flow, int lifetime)
{
    remove_flow_by_expiry(flow);
    flow->lifetime = lifetime;
    insert_flow_by_expiry(flow);
}

void inet_flow_free(InetFlow * flow)
{
    InetFlowPriv *priv = FLOW_PRIV(flow);
    InetFlowTable *table = priv->table;

    remove_flow_by_expiry(priv);
    g_hash_table_steal(table->table, priv);
    if (table->context_free && flow->context)
        table->context_free(flow->context);
    tcp_flow_free(priv->tcp);
    g_free(priv);
}

/* TCP connection tracking */
#define TCP_FIN                     0x0001
#define TCP_SYN                     0x0002
#define TCP_RST                     0x0004
#define TCP_ACK                     0x0010
#define TCP_MAX_WSCALE              14

#define SEQ_LT(a, b)                ((gint32) ((a) - (b)) < 0)
#define SEQ_LEQ(a, b)               ((gint32) ((a) - (b)) <= 0)
#define SEQ_GT(a, b)                ((gint32) ((a) - (b)) > 0)
#define SEQ_GEQ(a, b)               ((gint32) ((a) - (b)) >= 0)

/* Events that do not make a packet invalid, during and after the handshake */
#define TCP_HANDSHAKE_VALID_EVENTS  (INET_TCP_EVENT_SYN_RESEND | INET_TCP_EVENT_SYNACK_RESEND)
#define TCP_VALID_EVENTS            (INET_TCP_EVENT_RETRANSMISSION | INET_TCP_EVENT_BEFORE_LAST_ACK)

typedef struct _InetTcpPeer {
    guint32 isn;
    guint32 next_seq;           /* Sequence number after the last byte sent */
    guint32 last_ack;           /* Highest ACK number sent */
    guint32 window;             /* Last window advertised, scaled */
    guint32 last_ts;            /* Highest timestamp value sent */
    guint32 fin_seq;            /* Sequence number of the FIN */
    guint8 wscale;              /* Window scale offered in the SYN */
    gboolean wscale_offered;
    gboolean ts_offered;
    gboolean fin_sent;
} InetTcpPeer;

/* Connection state, shared by flows that carry the same connection */
typedef struct _InetTcpState {
    InetTcpConnState state;
    guint refcount;
    gboolean wscale_ok;         /* Both peers offered window scaling */
    gboolean ts_ok;             /* Both peers offered timestamps */
    InetTcpPeer client;
    InetTcpPeer server;
} InetTcpState;

/* The client end of a connection as seen in one flow. Linked flows see the
 * client at different addresses, so each flow has its own. */
typedef struct _InetTcpFlow {
    InetTcpState *state;
    gboolean client_known;
    guint16 client_port;        /* Client port in network byte order */
    InetAddr client_addr;
} InetTcpFlow;

static InetTcpFlow *tcp_flow_new(InetTcpState * state)
{
    InetTcpFlow *tcp_flow = g_malloc0(sizeof(InetTcpFlow));

    tcp_flow->state = state ? : g_malloc0(sizeof(InetTcpState));
    tcp_flow->state->refcount++;
    return tcp_flow;
}

static void tcp_flow_free(InetTcpFlow * tcp_flow)
{
    if (tcp_flow) {
        if (--tcp_flow->state->refcount == 0)
            g_free(tcp_flow->state);
        g_free(tcp_flow);
    }
}

static guint32 tcp_seg_len(InetPacket * pkt)
{
    return pkt->payload_length + ! !(pkt->tcp.flags & TCP_SYN) + ! !(pkt->tcp.flags & TCP_FIN);
}

static void tcp_peer_syn(InetTcpPeer * peer, InetPacket * pkt)
{
    peer->isn = pkt->tcp.seq;
    peer->next_seq = pkt->tcp.seq + 1;
    peer->window = pkt->tcp.window;
    peer->wscale_offered = ! !(pkt->tcp.options & INET_TCP_OPT_WSCALE);
    peer->wscale = MIN(pkt->tcp.wscale, TCP_MAX_WSCALE);
    peer->ts_offered = ! !(pkt->tcp.options & INET_TCP_OPT_TIMESTAMP);
    peer->last_ts = pkt->tcp.ts_val;
}

/* Record the data, ACK and window of a valid packet */
static void tcp_peer_update(InetTcpState * tcp, InetTcpPeer * peer, InetPacket * pkt)
{
    guint32 end = pkt->tcp.seq + tcp_seg_len(pkt);

    if (SEQ_GT(end, peer->next_seq))
        peer->next_seq = end;
    if ((pkt->tcp.flags & TCP_ACK) && SEQ_GT(pkt->tcp.ack, peer->last_ack))
        peer->last_ack = pkt->tcp.ack;
    /* The window in a SYN or SYN/ACK is never scaled */
    if (!(pkt->tcp.flags & TCP_SYN))
        peer->window = (guint32) pkt->tcp.window << (tcp->wscale_ok ? peer->wscale : 0);
    if ((pkt->tcp.options & INET_TCP_OPT_TIMESTAMP) && SEQ_GT(pkt->tcp.ts_val, peer->last_ts))
        peer->last_ts = pkt->tcp.ts_val;
    if (pkt->tcp.flags & TCP_FIN) {
        peer->fin_sent = TRUE;
        peer->fin_seq = pkt->tcp.seq + pkt->payload_length;
    }
}

/* A RST is valid when its sequence number is inside the receive window */
static gboolean tcp_rst_valid(InetTcpPeer * receiver, InetPacket * pkt)
{
    return SEQ_GEQ(pkt->tcp.seq, receiver->last_ack) && SEQ_LEQ(pkt->tcp.seq, receiver->last_ack + MAX(receiver->window, 1));
}

static guint32 tcp_handshake(InetTcpState * tcp, InetTcpPeer * sender, InetTcpPeer * receiver, gboolean from_client, InetPacket * pkt)
{
    guint16 flags = pkt->tcp.flags;

    if (flags & TCP_RST) {
        /* In SYN_SENT a RST must acknowledge the SYN. In SYN_RECV the client
         * has not acknowledged anything yet, so a RST from the server must
         * carry the next sequence number. */
        if (tcp->state == INET_TCP_STATE_SYN_SENT ?
            (flags & TCP_ACK) && pkt->tcp.ack == receiver->next_seq :
            from_client ? tcp_rst_valid(receiver, pkt) : pkt->tcp.seq == sender->next_seq) {
            tcp->state = INET_TCP_STATE_CLOSED;
            return 0;
        }
        return INET_TCP_EVENT_INVALID_RST;
    }

    if ((flags & (TCP_SYN | TCP_ACK)) == TCP_SYN) {
        if (!from_client) {
            /* A SYN from the server while waiting for the SYN/ACK is a
             * simultaneous open */
            if (tcp->state == INET_TCP_STATE_SYN_SENT) {
                tcp_peer_syn(sender, pkt);
                tcp->state = INET_TCP_STATE_SYN_RECV;
                return 0;
            }
            return INET_TCP_EVENT_SYN_WRONG_DIR;
        }
        if (pkt->tcp.seq == sender->isn)
            return INET_TCP_EVENT_SYN_RESEND;
        if (tcp->state == INET_TCP_STATE_SYN_SENT) {
            /* The client gave up on the old SYN and started again */
            tcp_peer_syn(sender, pkt);
            return 0;
        }
        return INET_TCP_EVENT_SYN_RESEND_DIFF_SEQ;
    }

    if (flags & TCP_SYN) {
        if (from_client)
            return INET_TCP_EVENT_SYNACK_WRONG_DIR;
        if (tcp->state == INET_TCP_STATE_SYN_RECV) {
            if (pkt->tcp.seq != sender->isn)
                return INET_TCP_EVENT_SYNACK_RESEND_DIFF_SEQ;
            if (pkt->tcp.ack != receiver->next_seq)
                return INET_TCP_EVENT_SYNACK_RESEND_DIFF_ACK;
            return INET_TCP_EVENT_SYNACK_RESEND;
        }
        if (pkt->tcp.ack != receiver->next_seq)
            return INET_TCP_EVENT_SYNACK_WRONG_ACK;
        tcp_peer_syn(sender, pkt);
        sender->last_ack = pkt->tcp.ack;
        tcp->wscale_ok = receiver->wscale_offered && sender->wscale_offered;
        tcp->ts_ok = receiver->ts_offered && sender->ts_offered;
        tcp->state = INET_TCP_STATE_SYN_RECV;
        return 0;
    }

    /* A packet without SYN or RST */
    if (tcp->state == INET_TCP_STATE_SYN_SENT) {
        if (from_client) {
            tcp->state = INET_TCP_STATE_ONE_SIDED;
            return INET_TCP_EVENT_ONE_SIDED;
        }
        return INET_TCP_EVENT_ACK_WRONG_DIR;
    }
    if (!from_client)
        return INET_TCP_EVENT_ACK_WRONG_DIR;
    if (!(flags & TCP_ACK) || pkt->tcp.ack != receiver->next_seq) {
        if (pkt->tcp.seq == sender->next_seq)
            return INET_TCP_EVENT_RIGHT_SEQ_WRONG_ACK;
        return INET_TCP_EVENT_WRONG_SEQ | INET_TCP_EVENT_INVALID_ACK;
    }
    if (pkt->tcp.seq != sender->next_seq)
        return INET_TCP_EVENT_WRONG_SEQ;
    receiver->last_ack = sender->isn + 1;
    tcp->state = INET_TCP_STATE_ESTABLISHED;
    return 0;
}

static void tcp_close(InetTcpState * tcp, InetTcpPeer * sender, InetTcpPeer * receiver, gboolean from_client, InetPacket * pkt)
{
    gboolean fin = ! !(pkt->tcp.flags & TCP_FIN);
    gboolean acks_fin = (pkt->tcp.flags & TCP_ACK) && receiver->fin_sent && SEQ_GT(pkt->tcp.ack, receiver->fin_seq);

    switch (tcp->state) {
    case INET_TCP_STATE_ESTABLISHED:
        if (fin)
            tcp->state = from_client ? INET_TCP_STATE_FIN_WAIT1 : INET_TCP_STATE_CLOSE_WAIT;
        break;
    case INET_TCP_STATE_FIN_WAIT1:
        if (!from_client && fin)
            tcp->state = acks_fin ? INET_TCP_STATE_TIME_WAIT : INET_TCP_STATE_CLOSING;
        else if (!from_client && acks_fin)
            tcp->state = INET_TCP_STATE_FIN_WAIT2;
        break;
    case INET_TCP_STATE_FIN_WAIT2:
        if (!from_client && fin)
            tcp->state = INET_TCP_STATE_TIME_WAIT;
        break;
    case INET_TCP_STATE_CLOSING:
        if (!from_client && acks_fin)
            tcp->state = INET_TCP_STATE_TIME_WAIT;
        break;
    case INET_TCP_STATE_CLOSE_WAIT:
        if (from_client && fin)
            tcp->state = INET_TCP_STATE_LAST_ACK;
        break;
    case INET_TCP_STATE_LAST_ACK:
        if (!from_client && acks_fin)
            tcp->state = INET_TCP_STATE_CLOSED;
        break;
    default:
        break;
    }
}

/* Check a packet on a connection that has completed the handshake */
static guint32 tcp_established(InetTcpState * tcp, InetTcpPeer * sender, InetTcpPeer * receiver, gboolean from_client, InetPacket * pkt)
{
    guint16 flags = pkt->tcp.flags;
    guint32 seq = pkt->tcp.seq;
    guint32 len = pkt->payload_length;
    guint32 events = 0;

    if (flags & TCP_SYN) {
        if (flags & TCP_ACK) {
            if (from_client)
                return INET_TCP_EVENT_SYNACK_WRONG_DIR;
            if (seq != sender->isn)
                return INET_TCP_EVENT_SYNACK_RESEND_DIFF_SEQ;
            if (pkt->tcp.ack != receiver->isn + 1)
                return INET_TCP_EVENT_SYNACK_RESEND_DIFF_ACK;
            return INET_TCP_EVENT_SYNACK_RESEND;
        }
        if (!from_client)
            return INET_TCP_EVENT_SYN_WRONG_DIR;
        return seq == sender->isn ? INET_TCP_EVENT_SYN_RESEND : INET_TCP_EVENT_SYN_RESEND_DIFF_SEQ;
    }

    if (flags & TCP_RST) {
        if (!tcp_rst_valid(receiver, pkt))
            return INET_TCP_EVENT_INVALID_RST;
        tcp->state = INET_TCP_STATE_CLOSED;
        return 0;
    }

    /* PAWS (RFC 7323). A RST is checked above without a timestamp. */
    if (tcp->ts_ok && (!(pkt->tcp.options & INET_TCP_OPT_TIMESTAMP) || SEQ_LT(pkt->tcp.ts_val, sender->last_ts)))
        events |= INET_TCP_EVENT_INVALID_TIMESTAMP;

    if ((flags & TCP_ACK) && SEQ_GT(pkt->tcp.ack, receiver->next_seq))
        events |= INET_TCP_EVENT_INVALID_ACK;

    /* A keep-alive repeats the last byte sent, or sends no data, one before
     * the next sequence number */
    if (len <= 1 && !(flags & TCP_FIN) && seq == sender->next_seq - 1)
        return events;

    /* Data after the sender's FIN */
    if (sender->fin_sent && SEQ_GT(seq + len, sender->fin_seq + 1))
        events |= INET_TCP_EVENT_WRONG_SEQ;
    else if (len && SEQ_LEQ(seq + len, receiver->last_ack))
        events |= INET_TCP_EVENT_RETRANSMISSION | INET_TCP_EVENT_BEFORE_LAST_ACK;
    else if (SEQ_GT(seq, receiver->last_ack + receiver->window))
        events |= INET_TCP_EVENT_OUT_OF_WINDOW;
    else if (len && SEQ_LT(seq, sender->next_seq))
        events |= INET_TCP_EVENT_RETRANSMISSION;

    if (!(events & ~TCP_VALID_EVENTS))
        tcp_close(tcp, sender, receiver, from_client, pkt);
    return events;
}

/* The flow direction comes from the last SYN seen, so a SYN from the server
 * would swap it. Identify the client by the address and port of the first SYN. */
static gboolean tcp_from_client(InetTcpFlow * tcp_flow, InetPacket * pkt)
{
    InetTuple *t = &pkt->tuple;

    if (!tcp_flow->client_known)
        return FALSE;
    if (t->sport != t->dport)
        return t->sport == tcp_flow->client_port;
    return addr_compare(t, &t->src, &tcp_flow->client_addr) == 0;
}

static gboolean tcp_update(InetFlow * flow, InetPacket * pkt)
{
    InetTcpFlow *tcp_flow;
    InetTcpState *tcp;
    InetTcpPeer *sender, *receiver;
    gboolean from_client;
    guint32 events = 0;
    guint32 valid_events = TCP_VALID_EVENTS;

    pkt->tcp.events = 0;
    pkt->tcp.invalid = FALSE;
    pkt->tcp.state = inet_flow_tcp_state(flow);
    if (inet_flow_protocol(flow) != IP_PROTOCOL_TCP || !pkt->l4 || !pkt->payload)
        return TRUE;

    if (!FLOW_PRIV(flow)->tcp)
        FLOW_PRIV(flow)->tcp = tcp_flow_new(NULL);
    tcp_flow = FLOW_PRIV(flow)->tcp;
    tcp = tcp_flow->state;

    if (tcp->state == INET_TCP_STATE_NONE) {
        if ((pkt->tcp.flags & (TCP_SYN | TCP_ACK | TCP_RST)) == TCP_SYN) {
            tcp_peer_syn(&tcp->client, pkt);
            tcp_flow->client_port = pkt->tuple.sport;
            tcp_flow->client_addr = pkt->tuple.src;
            tcp_flow->client_known = TRUE;
            tcp->state = INET_TCP_STATE_SYN_SENT;
            return TRUE;
        }
        if ((pkt->tcp.flags & (TCP_SYN | TCP_ACK)) != (TCP_SYN | TCP_ACK)) {
            tcp->state = INET_TCP_STATE_UNTRACKED;
            return TRUE;
        }
        tcp->state = INET_TCP_STATE_ONE_SIDED;
    }

    from_client = tcp_from_client(tcp_flow, pkt);
    sender = from_client ? &tcp->client : &tcp->server;
    receiver = from_client ? &tcp->server : &tcp->client;

    switch (tcp->state) {
    case INET_TCP_STATE_UNTRACKED:
    case INET_TCP_STATE_CLOSED:
        return TRUE;
    case INET_TCP_STATE_ONE_SIDED:
        events = INET_TCP_EVENT_ONE_SIDED;
        break;
    case INET_TCP_STATE_SYN_SENT:
    case INET_TCP_STATE_SYN_RECV:
        events = tcp_handshake(tcp, sender, receiver, from_client, pkt);
        valid_events = TCP_HANDSHAKE_VALID_EVENTS;
        break;
    default:
        events = tcp_established(tcp, sender, receiver, from_client, pkt);
        break;
    }

    pkt->tcp.events = events;
    pkt->tcp.invalid = (events & ~valid_events) != 0;
    if (!pkt->tcp.invalid && tcp->state != INET_TCP_STATE_ONE_SIDED)
        tcp_peer_update(tcp, sender, pkt);
    return !pkt->tcp.invalid;
}

InetTcpConnState inet_flow_tcp_state(InetFlow * flow)
{
    return FLOW_PRIV(flow)->tcp ? FLOW_PRIV(flow)->tcp->state->state : INET_TCP_STATE_NONE;
}

void inet_flow_tcp_link(InetFlow * flow, InetFlow * linked, const InetAddr * client, guint16 client_port)
{
    InetTcpFlow *tcp_flow;

    if (!FLOW_PRIV(flow)->tcp)
        FLOW_PRIV(flow)->tcp = tcp_flow_new(NULL);
    tcp_flow = tcp_flow_new(FLOW_PRIV(flow)->tcp->state);
    tcp_flow->client_known = TRUE;
    tcp_flow->client_port = client_port;
    tcp_flow->client_addr = *client;
    /* State tracked on the linked flow before the link is incomplete */
    tcp_flow_free(FLOW_PRIV(linked)->tcp);
    FLOW_PRIV(linked)->tcp = tcp_flow;
}

/* Update the flow state and lifetime for a packet, and find the direction of
 * the packet. The lifetime is changed while the flow is out of the expiry
 * queues. */
static void inet_flow_update_tcp(InetFlowPriv * flow, InetFlowPriv * packet)
{
    /* FIN */
    if (CHECK_BIT(packet->flags, 0)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->pub.state = FLOW_CLOSED;
            flow->lifetime = LIFETIME_CLOSED;
        }
    }
    /* SYN */
    else if (CHECK_BIT(packet->flags, 1)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->pub.state = FLOW_OPEN;
            flow->lifetime = LIFETIME_OPEN;
        } else {
            flow->pub.state = FLOW_NEW;
            flow->lifetime = LIFETIME_NEW;
            flow->server_port = inet_tuple_get_dst_port(&packet->pub.tuple);
        }
    }
    /* RST */
    else if (CHECK_BIT(packet->flags, 2)) {
        flow->pub.state = FLOW_CLOSED;
        flow->lifetime = LIFETIME_CLOSED;
    }

    packet->pub.direction = inet_tuple_get_dst_port(&packet->pub.tuple) == flow->server_port ?
        FLOW_DIRECTION_ORIGINAL : FLOW_DIRECTION_REPLY;
}

static void inet_flow_update_udp(InetFlowPriv * flow, InetFlowPriv * packet)
{
    packet->pub.direction =
        inet_tuple_get_dst_port(&packet->pub.tuple) <
        inet_tuple_get_src_port(&packet->pub.tuple) ? FLOW_DIRECTION_ORIGINAL : FLOW_DIRECTION_REPLY;

    if (flow->pub.direction && packet->pub.direction && packet->pub.direction != flow->pub.direction) {
        flow->pub.state = FLOW_OPEN;
        flow->lifetime = LIFETIME_OPEN;
    }
}

static void inet_flow_update(InetFlowPriv * flow, InetFlowPriv * packet)
{
    remove_flow_by_expiry(flow);
    if (inet_flow_protocol(&flow->pub) == IP_PROTOCOL_TCP) {
        inet_flow_update_tcp(flow, packet);
    } else if (inet_flow_protocol(&flow->pub) == IP_PROTOCOL_UDP) {
        inet_flow_update_udp(flow, packet);
    }
    insert_flow_by_expiry(flow);
    flow->pub.direction = packet->pub.direction;
}

InetFlow *inet_flow_expire(InetFlowTable * table, guint64 timestamp)
{
    int i;

    for (i = 0; i < LIFETIME_COUNT; i++) {
        GList *first = g_queue_peek_head_link(table->expire_queue[i]);
        if (first) {
            InetFlow *flow = (InetFlow *) first->data;
            if (flow->timestamp + table->timeout_us[i] <= timestamp) {
                return flow;
            }
        }
    }
    return NULL;
}

/* Parse a frame into pkt. On failure the status says why. */
static gboolean packet_parse(InetPacket * pkt, const guint8 * frame, guint length,
                             InetFragList * fragments, guint64 timestamp, guint32 flags)
{
    gboolean parsed;

    memset(pkt, 0, sizeof(*pkt));
    if (flags & INET_FLOW_L2)
        parsed = flow_parse(pkt, frame, length, fragments, timestamp, flags);
    else
        parsed = flow_parse_ip(pkt, frame, length, fragments, timestamp, flags);
    if (!parsed && pkt->status == INET_PACKET_OK)
        pkt->status = INET_PACKET_PARSE_ERROR;
    return parsed;
}

gboolean inet_packet_parse(const guint8 * frame, guint length, guint32 flags, InetFragList * fragments, InetPacket * pkt)
{
    return packet_parse(pkt, frame, length, fragments, 0, flags);
}

static void flow_count(InetFlowPriv * flow, InetFlowPriv * packet, guint length)
{
    if (packet->pub.direction == FLOW_DIRECTION_ORIGINAL)
        flow->pub.outbytes += length;
    else if (packet->pub.direction == FLOW_DIRECTION_REPLY)
        flow->pub.inbytes += length;
    flow->pub.packets++;
}

static InetFlowPriv *flow_new(InetFlowTable * table, const InetTuple * tuple, guint64 timestamp)
{
    InetFlowPriv *flow;

    /* Check if max table size is reached */
    if (table->max > 0 && g_hash_table_size(table->table) >= table->max)
        return NULL;

    flow = g_malloc0(sizeof(InetFlowPriv));
    flow->table = table;
    flow->list.data = flow;
    flow->lifetime = LIFETIME_NEW;
    flow->pub.tuple = *tuple;
    flow->pub.timestamp = timestamp ? : get_time_us();
    if (!g_hash_table_insert(table->table, flow, flow)) {
        gpointer existing;

        /* The tuple has a flow. The hash table has no destroy functions,
         * so the insert freed nothing, but it kept the existing flow as the
         * key and made the new flow the value. Put the existing flow back. */
        g_hash_table_lookup_extended(table->table, flow, &existing, NULL);
        g_hash_table_insert(table->table, existing, existing);
        g_free(flow);
        return NULL;
    }
    insert_flow_by_expiry(flow);
    return flow;
}

InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length, guint64 timestamp, guint32 flags, InetPacket * pkt)
{
    InetFlowPriv packet = {.pub.timestamp = timestamp };
    InetPacket tmp_pkt;
    InetFlowPriv *flow;

    if (!pkt)
        pkt = &tmp_pkt;
    if (!packet_parse(pkt, frame, length, table->frag_info_list, timestamp, flags))
        return NULL;

    packet.pub.tuple = pkt->tuple;
    packet.flags = pkt->tcp.flags;
    flow = g_hash_table_lookup(table->table, &packet);
    /* The lookup hashed the packet tuple, and a new flow keeps the hash */
    pkt->tuple.hash = packet.pub.tuple.hash;
    if (flow) {
        if (flags & INET_FLOW_UPDATE) {
            inet_flow_update(flow, &packet);
            flow->pub.timestamp = timestamp ? : get_time_us();
            flow_count(flow, &packet, length);
        }
        table->hits++;
    } else {
        if (!(flags & INET_FLOW_CREATE)) {
            pkt->status = INET_PACKET_NOT_FOUND;
            return NULL;
        }
        flow = flow_new(table, &packet.pub.tuple, timestamp);
        if (!flow) {
            pkt->status = INET_PACKET_TABLE_FULL;
            return NULL;
        }
        table->misses++;
        inet_flow_update(flow, &packet);
        flow_count(flow, &packet, length);
    }
    pkt->direction = packet.pub.direction;
    if (flags & INET_FLOW_TCP_TRACK)
        tcp_update(&flow->pub, pkt);
    return &flow->pub;
}

InetFlow *inet_flow_create(InetFlowTable * table, const InetTuple * tuple, guint64 timestamp)
{
    InetFlowPriv *flow = flow_new(table, tuple, timestamp);

    return flow ? &flow->pub : NULL;
}

void inet_flow_table_free(InetFlowTable * table)
{
    int i;

    /* Every flow is in one expiry queue */
    for (i = 0; i < LIFETIME_COUNT; i++) {
        while (!g_queue_is_empty(table->expire_queue[i]))
            inet_flow_free(g_queue_peek_head(table->expire_queue[i]));
    }
    g_hash_table_destroy(table->table);
    inet_frag_list_free(table->frag_info_list);
    for (i = 0; i < LIFETIME_COUNT; i++) {
        g_queue_free(table->expire_queue[i]);
    }
    g_free(table);
}

InetFlowTable *inet_flow_table_new(void)
{
    InetFlowTable *table = g_malloc0(sizeof(InetFlowTable));
    int i;

    /* The table frees its flows itself. A destroy function would free an
     * existing flow when a flow with the same tuple is inserted. */
    table->table = g_hash_table_new((GHashFunc) flow_hash, (GEqualFunc) flow_compare);
    table->frag_info_list = inet_frag_list_new(INET_FRAG_DEFAULT_MAX, INET_FRAG_DEFAULT_TIMEOUT);
    /* Choose the hash multipliers now, and not on the first packet */
    hash_keys_init();
    for (i = 0; i < LIFETIME_COUNT; i++) {
        table->expire_queue[i] = g_queue_new();
        table->timeout_us[i] = (guint64) default_timeouts[i] * TIMESTAMP_RESOLUTION_US;
    }
    return table;
}

guint inet_flow_table_size(InetFlowTable * table)
{
    return g_hash_table_size(table->table);
}

void inet_flow_table_context_free_set(InetFlowTable * table, GDestroyNotify context_free)
{
    table->context_free = context_free;
}

void inet_flow_table_max_set(InetFlowTable * table, guint64 max_flows)
{
    table->max = max_flows;
}

void inet_flow_table_timeouts_set(InetFlowTable * table, guint new_s, guint open_s, guint closed_s)
{
    table->timeout_us[LIFETIME_NEW] = (guint64) new_s *TIMESTAMP_RESOLUTION_US;
    table->timeout_us[LIFETIME_OPEN] = (guint64) open_s *TIMESTAMP_RESOLUTION_US;
    table->timeout_us[LIFETIME_CLOSED] = (guint64) closed_s *TIMESTAMP_RESOLUTION_US;
}

void inet_flow_table_frag_limits_set(InetFlowTable * table, guint max_datagrams, guint timeout_s)
{
    frag_list_limits_set(table->frag_info_list, max_datagrams, timeout_s);
}

void inet_flow_foreach(InetFlowTable * table, IFFunc func, gpointer user_data)
{
    int i;

    if (table) {
        for (i = 0; i < LIFETIME_COUNT; i++) {
            g_queue_foreach(table->expire_queue[i], (GFunc) func, user_data);
        }
    }
}

InetFlow *inet_flow_lookup(InetFlowTable * table, const InetTuple * tuple)
{
    InetFlowPriv packet = { 0 };
    InetFlowPriv *flow;

    packet.pub.tuple = *tuple;
    flow = g_hash_table_lookup(table->table, &packet);
    return flow ? &flow->pub : NULL;
}

void inet_flow_establish(InetFlowTable * table, InetFlow * flow)
{
    flow->state = FLOW_OPEN;
    flow_lifetime_set(FLOW_PRIV(flow), LIFETIME_OPEN);
}

void inet_flow_close(InetFlowTable * table, InetFlow * flow)
{
    flow->state = FLOW_CLOSED;
    flow_lifetime_set(FLOW_PRIV(flow), LIFETIME_CLOSED);
}
