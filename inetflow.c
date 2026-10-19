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
#define TCP_FLAGS_MASK              0x01FF

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

static gboolean flow_parse_ipv4(InetPacket * pkt, const guint8 * data, guint32 length,
                                InetFragList * fragments, guint64 ts, guint32 flags);
static gboolean flow_parse_ipv6(InetPacket * pkt, const guint8 * data, guint32 length,
                                InetFragList * fragments, guint64 ts, guint32 flags);

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

void inet_tuple_set(InetTuple * tuple, guint8 family, guint8 protocol, const void *src,
                    guint16 sport, const void *dst, guint16 dport)
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

    return sport < dport ||
        (sport == dport && addr_compare(tuple, &tuple->src, &tuple->dst) < 0);
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

void inet_tuple_to_sockaddr(const InetTuple * tuple, gboolean src,
                            struct sockaddr_storage *out)
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
    return addr_compare(a, inet_tuple_server_addr(a), inet_tuple_server_addr(b)) == 0 &&
        inet_tuple_server_port(a) == inet_tuple_server_port(b) &&
        addr_compare(a, inet_tuple_client_addr(a), inet_tuple_client_addr(b)) == 0 &&
        inet_tuple_client_port(a) == inet_tuple_client_port(b);
}

gboolean inet_tuple_exact(const InetTuple * a, const InetTuple * b)
{
    if (a->protocol != b->protocol || a->family != b->family) {
        return FALSE;
    }
    return addr_compare(a, &a->src, &b->src) == 0 && a->sport == b->sport &&
        addr_compare(a, &a->dst, &b->dst) == 0 && a->dport == b->dport;
}

guint inet_tuple_hash(InetTuple * tuple)
{
    if (tuple->hash)
        return tuple->hash;

    guint16 lport = GUINT16_FROM_BE(inet_tuple_server_port(tuple));
    guint16 uport = GUINT16_FROM_BE(inet_tuple_client_port(tuple));
    tuple->hash = lport << 16 | uport;

    return tuple->hash;
}

static int find_flow_by_frag_info(gconstpointer a, gconstpointer b)
{
    InetFragment *entry = (InetFragment *) a;
    InetFragment *f = (InetFragment *) b;

    if (entry->id != f->id || entry->tuple.protocol != f->tuple.protocol) {
        return 1;
    }

    /* A datagram is identified by its source, destination, protocol and ID,
     * so a fragment in the other direction belongs to another datagram. The
     * ports are not in non-first fragments, so only the addresses are compared. */
    if (entry->tuple.family == f->tuple.family
        && addr_compare(&f->tuple, &entry->tuple.src, &f->tuple.src) == 0
        && addr_compare(&f->tuple, &entry->tuple.dst, &f->tuple.dst) == 0) {
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

    entry->tuple.sport = found_flow->tuple.sport;
    entry->tuple.dport = found_flow->tuple.dport;
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
    g_list_free_full(finished->head, free);
    g_rw_lock_writer_unlock(&finished->lock);
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

static inline void set_anomaly(InetPacket * pkt, guint32 anomaly)
{
    pkt->anomalies |= anomaly;
}

static void set_payload(InetPacket * pkt, const guint8 * data, guint32 length,
                        guint32 hdr_len)
{
    if (hdr_len <= length) {
        pkt->payload = data + hdr_len;
        pkt->payload_length = length - hdr_len;
    }
}

static gboolean flow_parse_tcp(InetPacket * pkt, const guint8 * data, guint32 length)
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
    else
        set_payload(pkt, data, length, hdr_len);
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
    if (GUINT16_FROM_BE(udp->length) < sizeof(udp_hdr_t) ||
        (!pkt->fragment && GUINT16_FROM_BE(udp->length) > length))
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
}

static gboolean flow_parse_gre(InetPacket * pkt, const guint8 * data, guint32 length,
                               InetFragList * fragments, guint64 ts, guint32 flags)
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
        if (!flow_parse_ipv4
            (pkt, data + offset, length - offset, fragments, ts, flags))
            return FALSE;
        break;
    case ETH_PROTOCOL_IPV6:
        if (!flow_parse_ipv6
            (pkt, data + offset, length - offset, fragments, ts, flags))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

static gboolean flow_parse_ipv4(InetPacket * pkt, const guint8 * data, guint32 length,
                                InetFragList * fragments, guint64 ts, guint32 flags)
{
    InetTuple *f = &pkt->tuple;
    ip_hdr_t *iph = (ip_hdr_t *) data;
    guint32 hdr_len;
    guint16 tot_len;

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
    tot_len = GUINT16_FROM_BE(iph->tot_len);
    if (tot_len < hdr_len)
        set_anomaly(pkt, INET_ANOMALY_IPV4_LEN_TOO_SMALL);
    else if (tot_len > length)
        set_anomaly(pkt, INET_ANOMALY_IPV4_TRUNCATED);
    else
        /* Ignore link layer padding after the end of the IP packet */
        length = tot_len;
    set_headers(pkt, data,
                (GUINT16_FROM_BE(iph->frag_off) & 0x1FFF) == 0 ? data + hdr_len : NULL);
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
            if (!flow_parse_tcp(pkt, data + hdr_len, length - hdr_len))
                return FALSE;
            break;
        case IP_PROTOCOL_UDP:
            if (!flow_parse_udp(pkt, data + hdr_len, length - hdr_len))
                return FALSE;
            break;
        case IP_PROTOCOL_GRE:
            if (flags & INET_FLOW_TUNNEL) {
                if (!flow_parse_gre(pkt, data + hdr_len, length - hdr_len, fragments, ts,
                                    flags))
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
    if (fragments && (GUINT16_FROM_BE(iph->frag_off) & 0x3FFF)) {
        InetFragment entry = { 0 };
        entry.id = iph->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments = !!(GUINT16_FROM_BE(iph->frag_off) & 0x2000);

        gboolean result = inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        if (!result)
            pkt->status = INET_PACKET_FRAG_UNTRACKED;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ipv6(InetPacket * pkt, const guint8 * data, guint32 length,
                                InetFragList * fragments, guint64 ts, guint32 flags)
{
    InetTuple *f = &pkt->tuple;
    ip6_hdr_t *iph = (ip6_hdr_t *) data;
    frag_hdr_t *fragment_hdr = NULL;
    auth_hdr_t *auth_hdr;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr;

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
        if (!flow_parse_tcp(pkt, data, length)) {
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
            if (!flow_parse_ipv4(pkt, data, length, fragments, ts, flags)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_IPV6:
        if (flags & INET_FLOW_TUNNEL)
            if (!flow_parse_ipv6(pkt, data, length, fragments, ts, flags)) {
                return FALSE;
            }
        break;
    case IP_PROTOCOL_GRE:
        if (flags & INET_FLOW_TUNNEL)
            if (!flow_parse_gre(pkt, data, length, fragments, ts, flags)) {
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
        fragment_hdr = (frag_hdr_t *) data;
        inet_tuple_set_protocol(f, fragment_hdr->next_hdr);
        pkt->fragment = TRUE;

        data += sizeof(frag_hdr_t);
        length -= sizeof(frag_hdr_t);

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
    if (fragments && fragment_hdr) {
        InetFragment entry = { 0 };
        entry.id = fragment_hdr->id;
        entry.tuple = *f;
        entry.timestamp = ts;

        gboolean more_fragments = !!(GUINT16_FROM_BE(fragment_hdr->fo_res_mflag) & 0x1);

        gboolean result = inet_frag_list_update(fragments, &entry, more_fragments);
        *f = entry.tuple;
        if (!result)
            pkt->status = INET_PACKET_FRAG_UNTRACKED;
        return result;
    }

    return TRUE;
}

static gboolean flow_parse_ip(InetPacket * pkt, const guint8 * data, guint32 length,
                              InetFragList * fragments, guint64 ts, guint32 flags)
{
    guint8 version;

    if (length < sizeof(version))
        return FALSE;

    version = *data;
    version = 0x0f & (version >> 4);

    if (version == 4) {
        if (!flow_parse_ipv4(pkt, data, length, fragments, ts, flags))
            return FALSE;
    } else if (version == 6) {
        if (!flow_parse_ipv6(pkt, data, length, fragments, ts, flags))
            return FALSE;
    } else {
        DEBUG("Unsupported ip version: %d\n", version);
        set_anomaly(pkt, INET_ANOMALY_IP_VERSION);
        return FALSE;
    }
    return TRUE;
}

static gboolean flow_parse(InetPacket * pkt, const guint8 * data, guint32 length,
                           InetFragList * fragments, guint64 ts, guint32 flags)
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

static void inet_flow_update_tcp(InetFlow * flow, InetFlow * packet)
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

static void inet_flow_update_udp(InetFlow * flow, InetFlow * packet)
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

static void inet_flow_update(InetFlow * flow, InetFlow * packet)
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

gboolean inet_packet_parse(const guint8 * frame, guint length, guint32 flags,
                           InetFragList * fragments, InetPacket * pkt)
{
    return packet_parse(pkt, frame, length, fragments, 0, flags);
}

static void flow_count(InetFlow * flow, InetFlow * packet, guint length)
{
    if (packet->direction == FLOW_DIRECTION_ORIGINAL)
        flow->outbytes += length;
    else if (packet->direction == FLOW_DIRECTION_REPLY)
        flow->inbytes += length;
    flow->packets++;
}

InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length,
                        guint64 timestamp, guint32 flags, InetPacket * pkt)
{
    InetFlow packet = {.timestamp = timestamp };
    InetPacket tmp_pkt;
    InetFlow *flow;

    if (!pkt)
        pkt = &tmp_pkt;
    if (!packet_parse(pkt, frame, length, table->frag_info_list, timestamp, flags))
        return NULL;

    packet.tuple = pkt->tuple;
    packet.flags = pkt->tcp.flags;
    flow = (InetFlow *) g_hash_table_lookup(table->table, &packet);
    if (flow) {
        if (flags & INET_FLOW_UPDATE) {
            remove_flow_by_expiry(table, flow, flow->lifetime);
            inet_flow_update(flow, &packet);
            insert_flow_by_expiry(table, flow, flow->lifetime);
            flow->timestamp = timestamp ? : get_time_us();
            flow_count(flow, &packet, length);
        }
        table->hits++;
    } else {
        if (!(flags & INET_FLOW_CREATE)) {
            pkt->status = INET_PACKET_NOT_FOUND;
            return NULL;
        }
        /* Check if max table size is reached */
        if (table->max > 0 && g_hash_table_size(table->table) >= table->max) {
            pkt->status = INET_PACKET_TABLE_FULL;
            return NULL;
        }

        flow = (InetFlow *) g_malloc0(sizeof(InetFlow));
        flow->table = table;
        flow->list.data = flow;
        /* Set default lifetime before processing further - this may be over written */
        flow->lifetime = INET_FLOW_DEFAULT_NEW_TIMEOUT;
        flow->family = packet.tuple.family;
        flow->tuple = packet.tuple;
        g_hash_table_replace(table->table, (gpointer) flow, (gpointer) flow);
        table->misses++;
        flow->timestamp = timestamp ? : get_time_us();
        inet_flow_update(flow, &packet);
        insert_flow_by_expiry(table, flow, flow->lifetime);
        flow_count(flow, &packet, length);
    }
    pkt->direction = packet.direction;
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
    flow->family = tuple->family;
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
