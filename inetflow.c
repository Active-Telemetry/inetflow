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
#define FRAG_EXPIRY_TIME            30
#define MAX_FRAG_DEPTH              128

static int lifetime_values[] = {
    INET_FLOW_DEFAULT_CLOSED_TIMEOUT,
    INET_FLOW_DEFAULT_NEW_TIMEOUT,
    INET_FLOW_DEFAULT_OPEN_TIMEOUT,
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
} __attribute__((packed)) ethernet_hdr_t;

typedef struct vlan_hdr_t {
    guint16 tci;
    guint16 protocol;
} __attribute__((packed)) vlan_hdr_t;

typedef struct pppoe_sess_hdr {
    guint8 ver_type;
    guint8 code;
    guint16 session_id;
    guint16 payload_length;
    guint16 ppp_protocol_id;
} __attribute__((packed)) pppoe_sess_hdr_t;

#define GRE_HEADER_CSUM         0x8000
#define GRE_HEADER_ROUTING      0x4000
#define GRE_HEADER_KEY          0x2000
#define GRE_HEADER_SEQ          0x1000

typedef struct gre_hdr_t {
    guint16 flags_version;
    guint16 protocol;
} __attribute__((packed)) gre_hdr_t;

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
} __attribute__((packed)) ip_hdr_t;

typedef struct ip6_hdr_t {
    guint32 ver_tc_fl;
    guint16 pay_len;
    guint8 next_hdr;
    guint8 hop_limit;
    guint8 saddr[16];
    guint8 daddr[16];
} __attribute__((packed)) ip6_hdr_t;

typedef struct tcp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 seq;
    guint32 ack;
    guint16 flags;
    guint16 window;
    guint16 check;
    guint16 urg_ptr;
} __attribute__((packed)) tcp_hdr_t;

typedef struct udp_hdr_t {
    guint16 source;
    guint16 destination;
    guint16 length;
    guint16 check;
} __attribute__((packed)) udp_hdr_t;

typedef struct frag_hdr_t {
    guint8 next_hdr;
    guint8 res;
    guint16 fo_res_mflag;
    guint32 id;
} __attribute__((packed)) frag_hdr_t;

typedef struct auth_hdr_t {
    guint8 next_hdr;
    guint8 payload_len;
    guint16 reserved;
    guint64 spi_seq;
    guint64 icv;
} __attribute__((packed)) auth_hdr_t;

typedef struct sctp_hdr_t {
    guint16 source;
    guint16 destination;
    guint32 ver_tag;
    guint32 checksum;
} __attribute__((packed)) sctp_hdr_t;

typedef struct ipv6_partial_ext_hdr_t {
    guint8 next_hdr;
    guint8 hdr_ext_len;
} __attribute__((packed)) ipv6_partial_ext_hdr_t;

static gboolean flow_parse_ipv4(InetTuple * f, const guint8 * data, guint32 length,
                                InetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * flags, gboolean tunnel);
static gboolean flow_parse_ipv6(InetTuple * f, const guint8 * data, guint32 length,
                                InetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * flags, gboolean tunnel);

static inline guint64 get_time_us(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        return (now.tv_sec * (guint64) TIMESTAMP_RESOLUTION_US + (now.tv_nsec / 1000));
    else
        return 0;
}

static int sock_address_comparison(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (((struct sockaddr_in *)a)->sin_family != ((struct sockaddr_in *)a)->sin_family) {
        return 1;
    }

    if (((struct sockaddr_in *)a)->sin_family == AF_INET) {
        struct sockaddr_in *a_v4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b_v4 = (struct sockaddr_in *)b;
        return memcmp(&a_v4->sin_addr, &b_v4->sin_addr, sizeof(a_v4->sin_addr));
    } else {
        struct sockaddr_in6 *a_v6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b_v6 = (struct sockaddr_in6 *)b;
        return memcmp(&a_v6->sin6_addr, &b_v6->sin6_addr, sizeof(a_v6->sin6_addr));
    }
}

struct sockaddr_storage *inet_tuple_get_lower(InetTuple * tuple)
{
    guint16 sport = ((struct sockaddr_in *)&tuple->src)->sin_port;
    guint16 dport = ((struct sockaddr_in *)&tuple->dst)->sin_port;
    if (sport < dport ||
        (sport == 0 && dport == 0 && sock_address_comparison(&tuple->src, &tuple->dst) < 0))
        return &tuple->src;
    else
        return &tuple->dst;
}

struct sockaddr_storage *inet_tuple_get_upper(InetTuple * tuple)
{
    guint16 sport = ((struct sockaddr_in *)&tuple->src)->sin_port;
    guint16 dport = ((struct sockaddr_in *)&tuple->dst)->sin_port;
    if (dport > sport ||
        (dport == 0 && sport == 0 && sock_address_comparison(&tuple->dst, &tuple->src) > 0))
        return &tuple->dst;
    else
        return &tuple->src;
}

gboolean inet_tuple_equal(InetTuple * a, InetTuple * b)
{
    if (a->protocol != b->protocol) {
        return FALSE;
    }

    struct sockaddr_storage *lower_a = inet_tuple_get_lower(a);
    struct sockaddr_storage *upper_a = inet_tuple_get_upper(a);
    struct sockaddr_storage *lower_b = inet_tuple_get_lower(b);
    struct sockaddr_storage *upper_b = inet_tuple_get_upper(b);

    if (sock_address_comparison(lower_a, lower_b)) {
        return FALSE;
    }
    if (((struct sockaddr_in *)lower_a)->sin_port !=
        ((struct sockaddr_in *)lower_b)->sin_port) {
        return FALSE;
    }
    if (sock_address_comparison(upper_a, upper_b)) {
        return FALSE;
    }
    if (((struct sockaddr_in *)upper_a)->sin_port !=
        ((struct sockaddr_in *)upper_b)->sin_port) {
        return FALSE;
    }
    return TRUE;
}

gboolean inet_tuple_exact(InetTuple * a, InetTuple * b)
{
    if (a->protocol != b->protocol) {
        return FALSE;
    }

    struct sockaddr_storage *src_a = &a->src;
    struct sockaddr_storage *dst_a = &a->dst;
    struct sockaddr_storage *src_b = &b->src;
    struct sockaddr_storage *dst_b = &b->dst;

    if (sock_address_comparison(src_a, src_b)) {
        return FALSE;
    }
    if (sock_address_comparison(dst_a, dst_b)) {
        return FALSE;
    }
    return TRUE;
}

guint inet_tuple_hash(InetTuple * tuple)
{
    if (tuple->hash)
        return tuple->hash;

    struct sockaddr_storage *lower = inet_tuple_get_lower(tuple);
    struct sockaddr_storage *upper = inet_tuple_get_upper(tuple);

    tuple->hash =
        ((struct sockaddr_in *)lower)->
        sin_port << 16 | ((struct sockaddr_in *)upper)->sin_port;

    return tuple->hash;
}

static int find_flow_by_frag_info(gconstpointer a, gconstpointer b)
{
    InetFragment *entry = (InetFragment *) a;
    InetFragment *f = (InetFragment *) b;

    if (entry->id != f->id) {
        return 1;
    }

    /* This is similar to inet_tuple_equal but ignores ports as they
     * are missing from the fragmented packet. */
    struct sockaddr_storage *lower_a = inet_tuple_get_lower(&entry->tuple);
    struct sockaddr_storage *upper_a = inet_tuple_get_upper(&entry->tuple);

    struct sockaddr_storage *src_b = inet_tuple_get_lower(&f->tuple);
    struct sockaddr_storage *dst_b = inet_tuple_get_upper(&f->tuple);

    if (sock_address_comparison(lower_a, src_b) == 0
        && sock_address_comparison(upper_a, dst_b) == 0) {
        return 0;
    }
    if (sock_address_comparison(lower_a, dst_b) == 0
        && sock_address_comparison(upper_a, src_b) == 0) {
        return 0;
    }
    return 1;
}

static gboolean frag_is_expired(InetFragment * frag_info, guint64 timestamp)
{
    if (timestamp - frag_info->timestamp > FRAG_EXPIRY_TIME * TIMESTAMP_RESOLUTION_US)
        return TRUE;
    return FALSE;
}

static guint16 clear_expired_frag_info(InetFragList * frag_info_list, guint64 timestamp)
{
    guint16 cleared = 0;
    GList *l = frag_info_list->head;
    while (l != NULL) {
        GList *next = l->next;
        if (frag_is_expired(l->data, timestamp)) {
            struct frag_info *frag_info = (struct frag_info *)(l->data);
            free(l->data);
            frag_info_list->head = g_list_delete_link(frag_info_list->head, l);
            cleared += 1;
        }
        l = next;
    }
    return cleared;
}

static gboolean store_frag_info(InetFragList * fragments, InetFragment * f, guint64 ts)
{
    uint64_t timestamp = ts ? : get_time_us();
    guint32 id = f->id;

    g_rw_lock_writer_lock(&fragments->lock);
    if (g_list_length(fragments->head) >= MAX_FRAG_DEPTH) {
        if (clear_expired_frag_info(fragments, timestamp) == 0) {
            DEBUG("Fragment tracking limit reached\n");
            g_rw_lock_writer_unlock(&fragments->lock);
            return FALSE;
        }
    }
    InetFragment *entry = g_malloc0(sizeof(InetFragment));
    entry->id = id;
    entry->tuple = f->tuple;
    entry->timestamp = timestamp;
    fragments->head = g_list_prepend(fragments->head, entry);
    g_rw_lock_writer_unlock(&fragments->lock);
    return TRUE;
}

gboolean inet_frag_list_update(InetFragList * fragments, InetFragment * entry,
                               gboolean more_fragments)
{
    GList *match;

    /* If there are no more fragments, we need a write lock to remove the entry */
    (more_fragments ? g_rw_lock_reader_lock : g_rw_lock_writer_lock) (&fragments->lock);
    match = g_list_find_custom(fragments->head, entry, find_flow_by_frag_info);

    /* If we didn't find a match, store this fragment for later */
    if (!match) {
        (more_fragments ? g_rw_lock_reader_unlock :
         g_rw_lock_writer_unlock) (&fragments->lock);
        return store_frag_info(fragments, entry, entry->timestamp);
    }

    InetFragment *found_flow = match->data;

    /* Match source port / address etc - could be either way around */
    if (found_flow->tuple.src.ss_family == AF_INET) {
        ((struct sockaddr_in *)&entry->tuple.src)->sin_port =
            ((struct sockaddr_in *)&found_flow->tuple.src)->sin_port;
        ((struct sockaddr_in *)&entry->tuple.dst)->sin_port =
            ((struct sockaddr_in *)&found_flow->tuple.dst)->sin_port;
    } else {
        ((struct sockaddr_in6 *)&entry->tuple.src)->sin6_port =
            ((struct sockaddr_in6 *)&found_flow->tuple.src)->sin6_port;
        ((struct sockaddr_in6 *)&entry->tuple.dst)->sin6_port =
            ((struct sockaddr_in6 *)&found_flow->tuple.dst)->sin6_port;
    }
    /* If this is the last IP fragment (MF is unset), clean up the list */
    if (!more_fragments) {
        fragments->head = g_list_remove_link(fragments->head, match);
        free(match->data);
        g_list_free(match);
    }
    (more_fragments ? g_rw_lock_reader_unlock : g_rw_lock_writer_unlock) (&fragments->lock);
    return TRUE;
}

void inet_frag_list_free(InetFragList * finished)
{
    g_rw_lock_writer_lock(&finished->lock);
    g_rw_lock_clear(&finished->lock);
    free(finished);
}

InetFragList *inet_frag_list_new()
{
    InetFragList *new_list = calloc(1, sizeof(InetFragList));
    g_rw_lock_init(&new_list->lock);
    return new_list;
}

static guint32 get_hdr_len(guint8 hdr_ext_len)
{
    return (hdr_ext_len + IPV6_FIRST_8_OCTETS) * EIGHT_OCTET_UNITS;
}

static guint32 flow_hash(InetFlow * f)
{
    if (f->hash)
        return f->hash;

    f->hash = inet_tuple_hash(&f->tuple);

    return f->hash;
}

static gboolean flow_compare(InetFlow * f1, InetFlow * f2)
{
    return inet_tuple_equal(&f1->tuple, &f2->tuple);
}

static gboolean flow_parse_tcp(InetTuple * f, const guint8 * data, guint32 length,
                               guint16 * flags)
{
    tcp_hdr_t *tcp = (tcp_hdr_t *) data;
    if (length < sizeof(tcp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(tcp->source);
    guint16 dport = GUINT16_FROM_BE(tcp->destination);

    ((struct sockaddr_in *)&f->src)->sin_port = sport;
    ((struct sockaddr_in *)&f->dst)->sin_port = dport;

    if (flags) {
        *flags = GUINT16_FROM_BE(tcp->flags);
    }
    return TRUE;
}

static gboolean flow_parse_udp(InetTuple * f, const guint8 * data, guint32 length)
{
    udp_hdr_t *udp = (udp_hdr_t *) data;
    if (length < sizeof(udp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(udp->source);
    guint16 dport = GUINT16_FROM_BE(udp->destination);

    ((struct sockaddr_in *)&f->src)->sin_port = sport;
    ((struct sockaddr_in *)&f->dst)->sin_port = dport;

    return TRUE;
}

static gboolean flow_parse_sctp(InetTuple * f, const guint8 * data, guint32 length)
{
    sctp_hdr_t *sctp = (sctp_hdr_t *) data;
    if (length < sizeof(sctp_hdr_t))
        return FALSE;
    guint16 sport = GUINT16_FROM_BE(sctp->source);
    guint16 dport = GUINT16_FROM_BE(sctp->destination);

    ((struct sockaddr_in *)&f->src)->sin_port = sport;
    ((struct sockaddr_in *)&f->dst)->sin_port = dport;

    return TRUE;
}

static gboolean flow_parse_gre(InetTuple * f, const guint8 * data, guint32 length,
                               InetFragList * fragments, const uint8_t ** iphr, guint64 ts,
                               guint16 * tcp_flags)
{
    gre_hdr_t *gre = (gre_hdr_t *) data;
    if (length < sizeof(gre_hdr_t))
        return FALSE;
    int offset = sizeof(gre_hdr_t);
    guint16 flags = GUINT16_FROM_BE(gre->flags_version);
    guint16 proto = GUINT16_FROM_BE(gre->protocol);

    if (flags & (GRE_HEADER_CSUM | GRE_HEADER_ROUTING))
        offset += 4;
    if (flags & GRE_HEADER_KEY)
        offset += 4;
    if (flags & GRE_HEADER_SEQ)
        offset += 4;
    if (length < offset)
        return FALSE;

    DEBUG("Protocol: %d\n", proto);
    switch (proto) {
    case ETH_PROTOCOL_IP:
        if (!flow_parse_ipv4
            (f, data + offset, length - offset, fragments, iphr, ts, tcp_flags, TRUE))
            return FALSE;
        break;
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ipv6
            (f, data + offset, length - offset, fragments, iphr, ts, tcp_flags, TRUE))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

static gboolean flow_parse_ipv4(InetTuple * f, const guint8 * data, guint32 length,
                                InetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * tcp_flags, gboolean tunnel)
{
    ip_hdr_t *iph = (ip_hdr_t *) data;
    if (length < sizeof(ip_hdr_t))
        return FALSE;
    if (iphr) {
        *iphr = data;
    }

    ((struct sockaddr_in *)&f->src)->sin_family = AF_INET;
    ((struct sockaddr_in *)&f->dst)->sin_family = AF_INET;

    memcpy(&((struct sockaddr_in *)&f->src)->sin_addr, (char *)&iph->saddr,
           sizeof(((struct sockaddr_in *) & f->src)->sin_addr));
    memcpy(&((struct sockaddr_in *)&f->dst)->sin_addr, (char *)&iph->daddr,
           sizeof(((struct sockaddr_in *) & f->dst)->sin_addr));

    DEBUG("Protocol: %d\n", iph->protocol);
    inet_tuple_set_protocol(f, iph->protocol);

    f->offset += sizeof(ip_hdr_t);
    /* Don't bother with this for non-first fragments */
    if ((GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) == 0) {
        switch (iph->protocol) {
        case IP_PROTOCOL_TCP:
            if (!flow_parse_tcp
                (f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t), tcp_flags))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp(f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t)))
                return FALSE;
            break;
        case IP_PROTOCOL_GRE:
            if (tunnel) {
                if (!flow_parse_gre(f, data + sizeof(ip_hdr_t), length - sizeof(ip_hdr_t),
                                    fragments, iphr, ts, tcp_flags))
                    return FALSE;
            }
            break;
        case IP_PROTOCOL_ICMP:
        default:
            ((struct sockaddr_in *)&f->src)->sin_port = 0;
            ((struct sockaddr_in *)&f->dst)->sin_port = 0;
            break;
        }
    }

    /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
     * to find sport and dport. First fragments need to be saved.
     */
    if (fragments && (GUINT16_FROM_BE(iph->frag_off) & 0x3FFF)) {
        InetFragment entry = { 0 };
        entry.id = iph->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments = !!(GUINT16_FROM_BE(iph->frag_off) & 0x2000);

        gboolean result = inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ipv6(InetTuple * f, const guint8 * data, guint32 length,
                                InetFragList * fragments, const uint8_t ** iphr,
                                guint64 ts, guint16 * tcp_flags, gboolean tunnel)
{
    ip6_hdr_t *iph = (ip6_hdr_t *) data;
    frag_hdr_t *fragment_hdr = NULL;
    auth_hdr_t *auth_hdr;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr;

    if (length < sizeof(ip6_hdr_t))
        return FALSE;
    if (iphr)
        *iphr = data;

    ((struct sockaddr_in *)&f->src)->sin_family = AF_INET6;
    ((struct sockaddr_in *)&f->dst)->sin_family = AF_INET6;
    memcpy(&((struct sockaddr_in6 *)&f->src)->sin6_addr, (char *)&iph->saddr,
           sizeof(((struct sockaddr_in6 *) & f->src)->sin6_addr));
    memcpy(&((struct sockaddr_in6 *)&f->dst)->sin6_addr, (char *)&iph->daddr,
           sizeof(((struct sockaddr_in6 *) & f->dst)->sin6_addr));
    inet_tuple_set_protocol(f, iph->next_hdr);

    data += sizeof(ip6_hdr_t);
    length -= sizeof(ip6_hdr_t);
    f->offset += sizeof(ip6_hdr_t);

  next_header:
    DEBUG("Next Header: %u\n", inet_tuple_get_protocol(f));
    switch (inet_tuple_get_protocol(f)) {
    case IP_PROTOCOL_TCP:
        if (!flow_parse_tcp(f, data, length, tcp_flags)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_UDP:
        if (!flow_parse_udp(f, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_SCTP:
        if (!flow_parse_sctp(f, data, length)) {
            return FALSE;
        }
        break;
    case IP_PROTOCOL_IPV4:
        if (tunnel)
            if (!flow_parse_ipv4(f, data, length, fragments, iphr, ts, tcp_flags, tunnel)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_IPV6:
        if (tunnel)
            if (!flow_parse_ipv6(f, data, length, fragments, iphr, ts, tcp_flags, tunnel)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_GRE:
        if (tunnel)
            if (!flow_parse_gre(f, data, length, fragments, iphr, ts, tcp_flags)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        if (length < sizeof(ipv6_partial_ext_hdr_t))
            return FALSE;
        ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) data;
        if (length < get_hdr_len(ipv6_part_hdr->hdr_ext_len))
            return FALSE;
        inet_tuple_set_protocol(f, ipv6_part_hdr->next_hdr);
        data += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        length -= get_hdr_len(ipv6_part_hdr->hdr_ext_len);
        goto next_header;
    case IP_PROTOCOL_FRAGMENT:
        if (length < sizeof(frag_hdr_t))
            return FALSE;
        fragment_hdr = (frag_hdr_t *) data;
        inet_tuple_set_protocol(f, fragment_hdr->next_hdr);

        data += sizeof(frag_hdr_t);
        length -= sizeof(frag_hdr_t);

        /* Non-first IP fragments (frag_offset is non-zero) will need a look-up
         * to find sport and dport - there's no point continuing to parse.
         */
        if ((GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0xFFF8)) {
            break;
        }

        goto next_header;
    case IP_PROTOCOL_AUTH:
        if (length < sizeof(auth_hdr_t))
            return FALSE;
        auth_hdr = (auth_hdr_t *) data;
        if (length < (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS)
            return FALSE;
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
    if (fragments && fragment_hdr) {
        InetFragment entry = { 0 };
        entry.id = fragment_hdr->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments = !!(GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0x1);

        gboolean result = inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ip(InetTuple * f, const guint8 * data, guint32 length,
                              InetFragList * fragments,
                              const uint8_t ** iphr, guint64 ts, guint16 * flags,
                              gboolean tunnel)
{
    guint8 version;

    if (length < sizeof(version))
        return FALSE;

    version = *data;
    version = 0x0f & (version >> 4);

    if (version == 4) {
        if (!flow_parse_ipv4(f, data, length, fragments, iphr, ts, flags, tunnel))
            return FALSE;
    } else if (version == 6) {
        if (!flow_parse_ipv6(f, data, length, fragments, iphr, ts, flags, tunnel))
            return FALSE;
    } else {
        DEBUG("Unsupported ip version: %d\n", version);
        return FALSE;
    }
    return TRUE;
}

InetTuple *inet_flow_parse_ip(const guint8 * iphdr, guint length, InetFragList * fragments,
                              InetTuple * result, gboolean inspect_tunnel)
{
    if (!result)
        result = calloc(1, sizeof(InetTuple));
    flow_parse_ip(result, iphdr, length, fragments, NULL, 0, NULL, inspect_tunnel);
    return result;
}

static gboolean flow_parse(InetTuple * f, const guint8 * data, guint32 length,
                           InetFragList * fragments, const uint8_t ** iphr,
                           guint64 ts, guint16 * flags, gboolean tunnel)
{
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
        if (!flow_parse_ip(f, data, length, fragments, iphr, ts, flags, tunnel))
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

enum {
    FLOW_STATE = 1,
    FLOW_PACKETS,
    FLOW_HASH,
    FLOW_PROTOCOL,
    FLOW_LPORT,
    FLOW_UPORT,
    FLOW_SERVER_PORT,
    FLOW_LIP,
    FLOW_UIP,
    FLOW_SERVER_IP,
    FLOW_TUPLE,
    FLOW_DIRECTION,
    FLOW_LIFETIME,
    FLOW_TIMESTAMP,
};

static int find_expiry_index(guint64 lifetime)
{
    int i;

    for (i = 0; i < INET_FLOW_LIFETIME_COUNT; i++) {
        if (lifetime == lifetime_values[i]) {
            return i;
        }
    }
    return 0;
}

static void remove_flow_by_expiry(InetFlowTable * table, InetFlow * flow, guint64 lifetime)
{
    int index = find_expiry_index(lifetime);
    g_queue_unlink(table->expire_queue[index], &flow->list);
}

static void insert_flow_by_expiry(InetFlowTable * table, InetFlow * flow, guint64 lifetime)
{
    int index = find_expiry_index(lifetime);
    g_queue_push_tail_link(table->expire_queue[index], &flow->list);
}

void inet_flow_unref(InetFlow * flow)
{
    int index = find_expiry_index(flow->lifetime);
    g_queue_unlink(flow->table->expire_queue[index], &flow->list);
    g_hash_table_steal(flow->table->table, flow);
    g_free((gpointer) flow);
}

void inet_flow_update_tcp(InetFlow * flow, InetFlow * packet)
{
    /* FIN */
    if (CHECK_BIT(packet->flags, 0)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->state = FLOW_CLOSED;
            flow->lifetime = INET_FLOW_DEFAULT_CLOSED_TIMEOUT;
        }
    }
    /* SYN */
    else if (CHECK_BIT(packet->flags, 1)) {
        /* ACK */
        if (CHECK_BIT(packet->flags, 4)) {
            flow->state = FLOW_OPEN;
            flow->lifetime = INET_FLOW_DEFAULT_OPEN_TIMEOUT;
        } else {
            flow->state = FLOW_NEW;
            flow->lifetime = INET_FLOW_DEFAULT_NEW_TIMEOUT;
            flow->server_port = inet_tuple_get_dst_port(&packet->tuple);
        }
    }
    /* RST */
    else if (CHECK_BIT(packet->flags, 2)) {
        flow->state = FLOW_CLOSED;
        flow->lifetime = INET_FLOW_DEFAULT_CLOSED_TIMEOUT;
    }

    if (packet->direction == FLOW_DIRECTION_UNKNOWN) {
        packet->direction = inet_tuple_get_dst_port(&packet->tuple) == flow->server_port ?
            FLOW_DIRECTION_ORIGINAL : FLOW_DIRECTION_REPLY;
    }
}

void inet_flow_update_udp(InetFlow * flow, InetFlow * packet)
{
    packet->direction =
        inet_tuple_get_dst_port(&packet->tuple) <
        inet_tuple_get_src_port(&packet->tuple) ? FLOW_DIRECTION_ORIGINAL :
        FLOW_DIRECTION_REPLY;

    if (flow->direction && packet->direction && packet->direction != flow->direction) {
        flow->state = FLOW_OPEN;
        flow->lifetime = INET_FLOW_DEFAULT_OPEN_TIMEOUT;
    }
}

void inet_flow_update(InetFlow * flow, InetFlow * packet)
{
    if (inet_tuple_get_protocol(&flow->tuple) == IP_PROTOCOL_TCP) {
        inet_flow_update_tcp(flow, packet);
    } else if (inet_tuple_get_protocol(&flow->tuple) == IP_PROTOCOL_UDP) {
        inet_flow_update_udp(flow, packet);
    }
    flow->direction = packet->direction;
}

static void inet_flow_init(InetFlow * flow)
{
    memset(&flow->tuple, 0, sizeof(flow->tuple));
    flow->state = FLOW_NEW;
}

InetFlow *inet_flow_expire(InetFlowTable * table, guint64 ts)
{
    GList *iter;
    int i;

    for (i = 0; i < INET_FLOW_LIFETIME_COUNT; i++) {
        guint64 timeout = (lifetime_values[i] * TIMESTAMP_RESOLUTION_US);
        GList *first = g_queue_peek_head_link(table->expire_queue[i]);
        if (first) {
            InetFlow *flow = (InetFlow *) first->data;
            if (flow->timestamp + timeout <= ts) {
                return flow;
            }
        }
    }
    return NULL;
}

InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length)
{
    return inet_flow_get_full(table, frame, length, 0, 0, FALSE, TRUE, FALSE, NULL, NULL);
}

InetFlow *inet_flow_get_full(InetFlowTable * table,
                             const guint8 * frame, guint length,
                             guint16 hash, guint64 timestamp, gboolean update,
                             gboolean l2, gboolean inspect_tunnel, const uint8_t ** iphr,
                             InetTuple ** ret_tuple)
{
    InetFlow packet = {.timestamp = timestamp };
    InetTuple *tuple = NULL;
    InetTuple tmp_tuple = { 0 };
    InetFlow *flow = NULL;

    if (ret_tuple) {
        tuple = calloc(1, sizeof(InetTuple));
        *ret_tuple = tuple;
    } else {
        tuple = &tmp_tuple;
    }

    if (l2) {
        if (!flow_parse
            (tuple, frame, length, table->frag_info_list, iphr, timestamp,
             &packet.flags, inspect_tunnel)) {
            goto exit;
        }
    } else
        if (!flow_parse_ip
            (tuple, frame, length, table->frag_info_list, iphr, timestamp,
             &packet.flags, inspect_tunnel)) {
        goto exit;
    }

    packet.tuple = *tuple;
    packet.hash = 0;

    flow = (InetFlow *) g_hash_table_lookup(table->table, &packet);
    if (flow) {
        if (update) {
            remove_flow_by_expiry(table, flow, flow->lifetime);
            inet_flow_update(flow, &packet);
            insert_flow_by_expiry(table, flow, flow->lifetime);
            flow->timestamp = timestamp ? : get_time_us();
            flow->packets++;
            if (packet.direction == FLOW_DIRECTION_ORIGINAL)
                flow->outbytes += length;
            else if (packet.direction == FLOW_DIRECTION_REPLY)
                flow->inbytes += length;
        }
        table->hits++;
    } else {
        /* Check if max table size is reached */
        if (table->max > 0 && g_hash_table_size(table->table) >= table->max) {
            goto exit;
        }

        flow = (InetFlow *) g_malloc0(sizeof(InetFlow));
        flow->table = table;
        flow->list.data = flow;
        /* Set default lifetime before processing further - this may be over written */
        flow->lifetime = INET_FLOW_DEFAULT_NEW_TIMEOUT;
        flow->family = packet.family;
        flow->direction = packet.direction;
        flow->hash = packet.hash;
        flow->tuple = packet.tuple;
        if (packet.server_port) {
            flow->server_port = packet.server_port;
        }
        memcpy(flow->server_ip, packet.server_ip, sizeof(packet.server_ip));
        g_hash_table_replace(table->table, (gpointer) flow, (gpointer) flow);
        table->misses++;
        flow->timestamp = timestamp ? : get_time_us();
        inet_flow_update(flow, &packet);
        insert_flow_by_expiry(table, flow, flow->lifetime);
        flow->packets++;
        if (packet.direction == FLOW_DIRECTION_ORIGINAL)
            flow->outbytes += length;
        else if (packet.direction == FLOW_DIRECTION_REPLY)
            flow->inbytes += length;
    }
  exit:
    return flow;
}

InetFlow *inet_flow_create(InetFlowTable * table, InetTuple * tuple, uint64_t timestamp)
{
    InetFlow *flow;

    /* Check if max table size is reached */
    if (table->max > 0 && g_hash_table_size(table->table) >= table->max) {
        return NULL;
    }

    flow = (InetFlow *) g_malloc0(sizeof(InetFlow));
    flow->table = table;
    flow->list.data = flow;
    /* Set default lifetime before processing further */
    flow->lifetime = INET_FLOW_DEFAULT_NEW_TIMEOUT;
    flow->family = ((struct sockaddr *)&(tuple->src))->sa_family;
    flow->hash = inet_tuple_hash(tuple);
    flow->tuple = *tuple;
    g_hash_table_replace(table->table, (gpointer) flow, (gpointer) flow);
    flow->timestamp = timestamp ? : get_time_us();
    insert_flow_by_expiry(table, flow, flow->lifetime);

    return flow;
}

void inet_flow_table_unref(InetFlowTable * table)
{
    int i;

    g_hash_table_remove_all(table->table);
    g_hash_table_destroy(table->table);
    inet_frag_list_free(table->frag_info_list);
    for (i = 0; i < INET_FLOW_LIFETIME_COUNT; i++) {
        g_queue_free(table->expire_queue[i]);
    }
    g_free((gpointer) table);
}

static void inet_flow_table_init(InetFlowTable * table)
{
    int i;

    table->table =
        g_hash_table_new_full((GHashFunc) flow_hash, (GEqualFunc) flow_compare, NULL,
                              (GDestroyNotify) inet_flow_unref);
    table->frag_info_list = inet_frag_list_new();

    for (i = 0; i < INET_FLOW_LIFETIME_COUNT; i++) {
        table->expire_queue[i] = g_queue_new();
    }
}

InetFlowTable *inet_flow_table_new(void)
{
    InetFlowTable *table = (InetFlowTable *) g_malloc0(sizeof(InetFlowTable));
    inet_flow_table_init(table);
    return table;
}

void inet_flow_table_max_set(InetFlowTable * table, guint64 value)
{
    table->max = value;
}

void inet_flow_foreach(InetFlowTable * table, IFFunc func, gpointer user_data)
{
    int i;

    if (table) {
        for (i = 0; i < INET_FLOW_LIFETIME_COUNT; i++) {
            g_queue_foreach(table->expire_queue[i], (GFunc) func, user_data);
        }
    }
}

InetTuple *inet_flow_parse(const guint8 * frame, guint length, InetFragList * fragments,
                           InetTuple * result, gboolean inspect_tunnel)
{
    if (!result)
        result = calloc(1, sizeof(InetTuple));
    flow_parse(result, frame, length, fragments, NULL, 0, NULL, inspect_tunnel);
    return result;
}

InetFlow *inet_flow_lookup(InetFlowTable * table, InetTuple * tuple)
{
    InetFlow packet;

    packet.tuple = *tuple;
    packet.hash = 0;
    return (InetFlow *) g_hash_table_lookup(table->table, &packet);
}

void inet_flow_establish(InetFlowTable * table, InetFlow * flow)
{
    remove_flow_by_expiry(table, flow, flow->lifetime);
    flow->state = FLOW_OPEN;
    flow->lifetime = INET_FLOW_DEFAULT_OPEN_TIMEOUT;
    insert_flow_by_expiry(table, flow, flow->lifetime);
}

void inet_flow_close(InetFlowTable * table, InetFlow * flow)
{
    remove_flow_by_expiry(table, flow, flow->lifetime);
    flow->state = FLOW_CLOSED;
    flow->lifetime = INET_FLOW_DEFAULT_CLOSED_TIMEOUT;
    insert_flow_by_expiry(table, flow, flow->lifetime);
}
