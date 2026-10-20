/* inetflow - Unit tests
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
#include "inetflow.c"
#include <arpa/inet.h>
#include <pthread.h>

static InetPacket test_packet;
static InetTuple _test_tuple;
static InetTuple *test_tuple = &_test_tuple;
#define MAX_BUFFER_SIZE     1600

#define _TEST_SPORT 0x1234
uint16_t TEST_SPORT = _TEST_SPORT;
#define _TEST_DPORT 0x4321
uint16_t TEST_DPORT = _TEST_DPORT;
#define _TEST_SADDR 0x12345678
uint32_t TEST_SADDR = _TEST_SADDR;
#define _TEST_DADDR 0x87654321
uint32_t TEST_DADDR = _TEST_DADDR;

#define SYN        0x0002
#define SYN_ACK    0x0012
#define ACK        0x0010
#define FIN        0x0001
#define FIN_ACK    0x0011
#define RST        0x0004

static guint8 test_buffer[MAX_BUFFER_SIZE];
static guint8 test_src[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static guint8 test_dst[] = { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };

static guint8 test_ip6src[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

static guint8 test_ip6dst[] = {
    0xfc, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01
};

typedef struct icmp_hdr_t {
    guint8 type;
    guint8 code;
    guint16 chksum;
} __attribute__ ((packed)) icmp_hdr_t;

static guint8 *build_hdr_eth(guint8 * buffer, guint16 next_eth_protocol)
{
    guint8 *p = buffer;
    ethernet_hdr_t *eth = (ethernet_hdr_t *) p;
    memcpy(eth->destination, test_src, 6);
    memcpy(eth->source, test_dst, 6);
    eth->protocol = g_htons(next_eth_protocol);
    p += sizeof(ethernet_hdr_t);
    return p;
}

static guint8 *build_hdr_vlan(guint8 * buffer, guint16 vlan_protocol, guint16 next_protocol, int count)
{
    guint8 *p = buffer;

    for (int i = 1; i < count; i++) {
        vlan_hdr_t *vlan = (vlan_hdr_t *) p;
        vlan->tci = 0xc7db;
        vlan->protocol = g_htons(vlan_protocol);
        p += sizeof(vlan_hdr_t);
    }

    vlan_hdr_t *vlan = (vlan_hdr_t *) p;
    vlan->tci = 0xc7db;
    vlan->protocol = g_htons(next_protocol);
    p += sizeof(vlan_hdr_t);

    return p;
}

static guint8 *build_hdr_bad_ipv4(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x79;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = 0x1234;
    ip->frag_off = 0x0000;
    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = htonl(TEST_DADDR);
        ip->daddr = htonl(TEST_SADDR);
    } else {
        ip->saddr = htonl(TEST_SADDR);
        ip->daddr = htonl(TEST_DADDR);
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv4(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x45;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = 0x1234;
    ip->frag_off = 0x0000;
    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = htonl(TEST_DADDR);
        ip->daddr = htonl(TEST_SADDR);
    } else {
        ip->saddr = htonl(TEST_SADDR);
        ip->daddr = htonl(TEST_DADDR);
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv4_options(guint8 * buffer, guint next_ip_protocol, guint options_len)
{
    ip_hdr_t *ip = (ip_hdr_t *) buffer;
    guint8 *p = build_hdr_ipv4(buffer, next_ip_protocol, FALSE);

    ip->ihl_version = 0x40 | ((sizeof(ip_hdr_t) + options_len) / FOUR_BYTE_UNITS);
    /* Pad the options with No Operation options */
    memset(p, 0x01, options_len);
    return p + options_len;
}

static guint8 *build_hdr_ipv6(guint8 * buffer, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;
    ip6_hdr_t *ip6 = (ip6_hdr_t *) p;
    ip6->ver_tc_fl = g_htons(0x600d684a);
    ip6->pay_len = 0x28;
    ip6->next_hdr = next_ip_protocol;
    ip6->hop_limit = 0x40;
    if (reverse) {
        memcpy(ip6->saddr, test_ip6dst, 16);
        memcpy(ip6->daddr, test_ip6src, 16);
    } else {
        memcpy(ip6->saddr, test_ip6src, 16);
        memcpy(ip6->daddr, test_ip6dst, 16);
    }
    p += sizeof(ip6_hdr_t);
    return p;
}

static guint8 *build_hdr_sctp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    sctp_hdr_t *sctp_hdr = (sctp_hdr_t *) p;
    if (reverse) {
        sctp_hdr->source = TEST_DPORT;
        sctp_hdr->destination = TEST_SPORT;
    } else {
        sctp_hdr->source = TEST_SPORT;
        sctp_hdr->destination = TEST_DPORT;
    }
    sctp_hdr->ver_tag = 0x0;
    sctp_hdr->checksum = 0x1234;
    p += sizeof(sctp_hdr_t);
    return p;
}

static guint8 *build_hdr_fragment(guint8 * buffer, guint16 next_ip_protocol, gboolean more_frag_flag_set, guint16 offset, guint16 id)
{
    guint8 *p = buffer;
    frag_hdr_t *fragment_hdr = (frag_hdr_t *) p;
    fragment_hdr->next_hdr = next_ip_protocol;
    fragment_hdr->res = 0x0;
    if (more_frag_flag_set) {
        fragment_hdr->fo_res_mflag = GUINT16_TO_BE((offset << 3) + 1);
    } else {
        fragment_hdr->fo_res_mflag = GUINT16_TO_BE((offset << 3));
    }
    fragment_hdr->id = id;
    p += sizeof(frag_hdr_t);
    return p;
}

static guint8 *build_hdr_auth(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    auth_hdr_t *auth_hdr = (auth_hdr_t *) p;
    auth_hdr->next_hdr = next_ip_protocol;
    auth_hdr->payload_len = 4;
    auth_hdr->reserved;
    auth_hdr->spi_seq;
    auth_hdr->icv;
    p += (auth_hdr->payload_len + AH_HEADER_LEN_ADD) * FOUR_BYTE_UNITS;
    return p;
}

static guint8 *build_hdr_ipv6_part(guint8 * buffer, guint16 next_ip_protocol)
{
    guint8 *p = buffer;
    ipv6_partial_ext_hdr_t *ipv6_part_hdr = (ipv6_partial_ext_hdr_t *) p;
    ipv6_part_hdr->next_hdr = next_ip_protocol;
    ipv6_part_hdr->hdr_ext_len = 4;
    p += get_hdr_len(ipv6_part_hdr->hdr_ext_len);
    return p;
}

static guint8 *build_hdr_ipv6_ext(guint8 * buffer, guint ip_protocol, guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_IPV4:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    case IP_PROTOCOL_SCTP:
        p = build_hdr_sctp(p, reverse);
        break;
    case IP_PROTOCOL_HBH_OPT:
    case IP_PROTOCOL_DEST_OPT:
    case IP_PROTOCOL_ROUTING:
    case IP_PROTOCOL_MOBILITY:
    case IP_PROTOCOL_HIPV2:
    case IP_PROTOCOL_SHIM6:
        p = build_hdr_ipv6_part(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_FRAGMENT:
        p = build_hdr_fragment(p, next_ip_protocol, FALSE, 0x0, 0x0);
        break;
    case IP_PROTOCOL_AUTH:
        p = build_hdr_auth(p, next_ip_protocol);
        break;
    case IP_PROTOCOL_ESP:
    case IP_PROTOCOL_NO_NEXT_HDR:
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_pppoe(guint8 * buffer, guint next_ip_protocol, guint16 ppp_proto, gboolean reverse)
{
    guint8 *p = buffer;
    pppoe_sess_hdr_t *pppoe = (pppoe_sess_hdr_t *) p;
    pppoe->ver_type = 0x11;
    pppoe->code = 0x00;
    pppoe->session_id = 0x0001;
    pppoe->payload_length = 0x0032;
    pppoe->ppp_protocol_id = g_htons(ppp_proto);
    p += sizeof(pppoe_sess_hdr_t);
    switch (ppp_proto) {
    case PPP_PROTOCOL_IPV4:
    default:
        p = build_hdr_ipv4(p, next_ip_protocol, reverse);
        break;
    case PPP_PROTOCOL_IPV6:
        p = build_hdr_ipv6(p, next_ip_protocol, reverse);
        break;
    }
    return p;
}

static guint8 *build_hdr_tcp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    tcp_hdr_t *tcp = (tcp_hdr_t *) p;
    if (reverse) {
        tcp->source = htons(TEST_DPORT);
        tcp->destination = htons(TEST_SPORT);
    } else {
        tcp->source = htons(TEST_SPORT);
        tcp->destination = htons(TEST_DPORT);
    }
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->flags = 0;
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;
    p += sizeof(tcp_hdr_t);
    return p;
}

static guint8 *build_hdr_tcp_detail(guint8 * buffer, guint16 sport, guint16 dport, guint16 flags)
{
    guint8 *p = buffer;
    tcp_hdr_t *tcp = (tcp_hdr_t *) p;
    tcp->source = GUINT16_FROM_BE(sport);
    tcp->destination = GUINT16_FROM_BE(dport);
    tcp->seq = 0;
    tcp->ack = 0;
    tcp->flags = GUINT16_FROM_BE(flags);
    tcp->window = 0;
    tcp->check = 0;
    tcp->urg_ptr = 0;
    p += sizeof(tcp_hdr_t);
    return p;
}

static guint8 *build_hdr_udp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    udp_hdr_t *udp = (udp_hdr_t *) p;
    if (reverse) {
        udp->source = htons(TEST_DPORT);
        udp->destination = htons(TEST_SPORT);
    } else {
        udp->source = htons(TEST_SPORT);
        udp->destination = htons(TEST_DPORT);
    }
    udp->length = 0x0020;
    udp->check = 0x0000;
    p += sizeof(udp_hdr_t);
    return p;
}

static guint8 *build_hdr_icmp(guint8 * buffer, gboolean reverse)
{
    guint8 *p = buffer;
    icmp_hdr_t *icmp = (icmp_hdr_t *) p;
    icmp->type = 0x08;
    icmp->code = 0x00;;
    icmp->chksum = 0x4008;
    p += sizeof(icmp_hdr_t);
    return p;
}

static guint8 *build_hdr_gre(guint8 * buffer, guint16 protocol, gboolean reverse)
{
    guint8 *p = buffer;
    gre_hdr_t *gre = (gre_hdr_t *) p;
    gre->flags_version = 0;
    gre->protocol = GUINT16_TO_BE(protocol);
    p += sizeof(gre_hdr_t);
    return p;
}

static guint8 *build_hdr_after_ip(guint8 * buffer, guint ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (ip_protocol) {
    case IP_PROTOCOL_TCP:
        p = build_hdr_tcp(p, reverse);
        break;
    case IP_PROTOCOL_UDP:
        p = build_hdr_udp(p, reverse);
        break;
    case IP_PROTOCOL_SCTP:
        p = build_hdr_sctp(p, reverse);
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMPV6:
        p = build_hdr_icmp(p, reverse);
        break;
    default:
        return buffer;
    }
    return p;
}

static guint8 *build_hdr_ip(guint8 * buffer, guint16 eth_protocol, guint next_ip_protocol, gboolean reverse)
{
    guint8 *p = buffer;

    switch (eth_protocol) {
    case ETH_PROTOCOL_IP:
        p = build_hdr_ipv4(buffer, next_ip_protocol, reverse);
        break;
    case ETH_PROTOCOL_IPV6:
        p = build_hdr_ipv6(buffer, next_ip_protocol, reverse);
        break;
    default:
        return buffer;
    }

    return p;
}

static guint8 *build_tcp_segment(guint8 * buffer, gboolean reverse, guint16 flags,
                                 guint32 seq, guint32 ack, guint16 window, const char *payload)
{
    tcp_hdr_t *tcp = (tcp_hdr_t *) buffer;
    guint8 *p = build_hdr_tcp(buffer, reverse);

    tcp->flags = g_htons(0x5000 | flags);
    tcp->seq = g_htonl(seq);
    tcp->ack = g_htonl(ack);
    tcp->window = g_htons(window);
    if (payload) {
        memcpy(p, payload, strlen(payload));
        p += strlen(payload);
    }
    return p;
}

/* Build an Ethernet frame holding one TCP segment and set the IP length fields */
static guint make_tcp_pkt(guint8 * buffer, guint16 eth_protocol, gboolean reverse,
                          guint16 flags, guint32 seq, guint32 ack, guint16 window, const char *payload)
{
    guint8 *ip = build_hdr_eth(buffer, eth_protocol);
    guint8 *p = build_hdr_ip(ip, eth_protocol, IP_PROTOCOL_TCP, reverse);
    p = build_tcp_segment(p, reverse, flags, seq, ack, window, payload);

    if (eth_protocol == ETH_PROTOCOL_IP)
        ((ip_hdr_t *) ip)->tot_len = g_htons(p - ip);
    else
        ((ip6_hdr_t *) ip)->pay_len = g_htons(p - ip - sizeof(ip6_hdr_t));
    return (guint) (p - buffer);
}

static guint8 *build_hdr_ipv4_fragment(guint8 * buffer, guint next_ip_protocol,
                                       gboolean reverse, gboolean more_frag_flag_set, guint16 offset, guint16 id)
{
    guint8 *p = buffer;
    ip_hdr_t *ip = (ip_hdr_t *) p;
    ip->ihl_version = 0x45;
    ip->tos = 0x00;
    ip->tot_len = 0x0000;
    ip->id = id;
    if (more_frag_flag_set) {
        ip->frag_off = GUINT16_TO_BE(0x2000 + offset);
    } else {
        ip->frag_off = GUINT16_TO_BE(offset);
    }

    ip->ttl = 0xff;
    ip->protocol = next_ip_protocol;
    ip->check = 0x00;
    if (reverse) {
        ip->saddr = TEST_DADDR;
        ip->daddr = TEST_SADDR;
    } else {
        ip->saddr = TEST_SADDR;
        ip->daddr = TEST_DADDR;
    }
    p += sizeof(ip_hdr_t);
    return p;
}

static guint8 *build_hdr_ipv6_fragment(guint8 * buffer, guint next_ip_protocol,
                                       gboolean reverse, gboolean more_frag_flag_set, guint16 offset, guint16 id)
{
    guint8 *p = build_hdr_ip(buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_FRAGMENT, reverse);
    return build_hdr_fragment(p, next_ip_protocol, more_frag_flag_set, offset, id);
}

static guint8 *build_hdr_ip_fragment(guint8 * buffer,
                                     guint16 eth_protocol, guint next_ip_protocol,
                                     gboolean reverse, gboolean more_frag_flag_set, guint16 offset, guint16 id)
{
    guint8 *p = buffer;

    switch (eth_protocol) {
    case ETH_PROTOCOL_IP:
        p = build_hdr_ipv4_fragment(buffer, next_ip_protocol, reverse, more_frag_flag_set, offset, id);
        break;
    case ETH_PROTOCOL_IPV6:
        p = build_hdr_ipv6_fragment(buffer, next_ip_protocol, reverse, more_frag_flag_set, offset, id);
        break;
    default:
        return buffer;
    }

    return build_hdr_after_ip(p, next_ip_protocol, reverse);
}

static guint8 *build_pkt(guint8 * buffer, guint16 eth_protocol, guint ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, reverse);
    return build_hdr_after_ip(p, ip_protocol, reverse);
}

static guint make_pkt(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_reverse(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_pkt(buffer, eth_protocol, ip_protocol, TRUE);
    return (guint) (p - buffer);
}

static guint make_pkt_pppoe(guint8 * buffer, guint ip_protocol, guint16 ppp_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_PPPOE_SESS);
    p = build_hdr_pppoe(p, ip_protocol, ppp_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan(guint8 * buffer, guint16 eth_protocol, guint16 vlan_protocol, guint ip_protocol, int count)
{
    guint8 *p = build_hdr_eth(buffer, vlan_protocol);
    p = build_hdr_vlan(p, vlan_protocol, eth_protocol, count);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_vlan_Q_AD(guint8 * buffer, guint16 eth_protocol, guint ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_8021Q);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021Q, ETH_PROTOCOL_8021AD, 1);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021AD, eth_protocol, 1);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_mpls(guint8 * buffer, guint32 label, guint16 eth_protocol, guint ip_protocol, int count)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_MPLS_UC);
    while (count > 1) {
        *((guint32 *) p) = g_htonl(((label << 20) | 0xFF));
        p += sizeof(guint32);
        count--;
    };
    *((guint32 *) p) = g_htonl(((label << 20) | 0x1FF));
    p += sizeof(guint32);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_ipv6_ext(guint8 * buffer, guint16 next_ip_protocol, gboolean reverse)
{
    guint8 *p = build_hdr_ip(buffer, ETH_PROTOCOL_IPV6, next_ip_protocol, FALSE);

    if (next_ip_protocol != IP_PROTOCOL_NO_NEXT_HDR) {
        if (next_ip_protocol == IP_PROTOCOL_IPV4) {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMP, reverse);
        } else {
            p = build_hdr_ipv6_ext(p, next_ip_protocol, IP_PROTOCOL_ICMPV6, reverse);
        }
        p = build_hdr_after_ip(p, IP_PROTOCOL_ICMPV6, FALSE);
    }
    return (guint) (p - buffer);
}

static guint make_pkt_gre(guint8 * buffer, guint16 eth_protocol, guint16 gre_protocol, guint ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, IP_PROTOCOL_GRE, FALSE);
    p = build_hdr_gre(p, gre_protocol, FALSE);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, FALSE);
    p = build_hdr_after_ip(p, ip_protocol, FALSE);
    return (guint) (p - buffer);
}

#define FLOW_GET        (INET_FLOW_CREATE | INET_FLOW_UPDATE | INET_FLOW_L2)
#define FLOW_GET_IP     (INET_FLOW_CREATE | INET_FLOW_UPDATE)

/* Parse a frame that starts with Ethernet and copy out the tuple */
static gboolean parse_tuple(InetTuple * tuple, const guint8 * frame, guint length, gboolean tunnel)
{
    InetPacket pkt = { 0 };
    gboolean parsed = flow_parse(&pkt, frame, length, NULL, 0, tunnel ? INET_FLOW_TUNNEL : 0);

    if (tuple)
        *tuple = pkt.tuple;
    return parsed;
}

/* Parse a packet that starts with IPv6 and copy out the tuple */
static gboolean parse_ipv6_tuple(InetTuple * tuple, const guint8 * frame, guint length, gboolean tunnel)
{
    InetPacket pkt = { 0 };
    gboolean parsed = flow_parse_ipv6(&pkt, frame, length, NULL, 0, tunnel ? INET_FLOW_TUNNEL : 0, 0);

    *tuple = pkt.tuple;
    return parsed;
}

static void setup_test()
{
    memset(test_tuple, 0, sizeof(*test_tuple));
    memset(test_buffer, 0, MAX_BUFFER_SIZE);
}

void test_flow_parse_null_flow()
{
    setup_test();
    g_assert_false(flow_parse(NULL, test_buffer, 64, NULL, 0, 0));
}

void test_flow_parse_null_buffer()
{
    setup_test();
    g_assert_false(parse_tuple(test_tuple, NULL, 64, FALSE));
}

void test_flow_parse_0_length()
{
    setup_test();
    g_assert_false(parse_tuple(test_tuple, test_buffer, 0, FALSE));
}

void test_flow_parse_less_than_eth_length()
{
    setup_test();
    g_assert_false(parse_tuple(test_tuple, test_buffer, sizeof(ethernet_hdr_t) - 1, FALSE));
}

void test_flow_parse_udp()
{
    setup_test();

    InetTuple *test = calloc(1, sizeof(InetTuple));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(test, test_buffer, len, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(test, test_buffer, len, FALSE));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(test, test_buffer, len, FALSE));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(test, test_buffer, len, FALSE));
    free(test);
}

void test_flow_parse_tcp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* Reverse */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_icmp()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_pppoe()
{
    setup_test();

    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_vlan()
{
    setup_test();

    guint len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                              1);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP, 2);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD, IP_PROTOCOL_ICMPV6, 1);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD, IP_PROTOCOL_ICMPV6, 2);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_vlan_Q_AD(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_mpls()
{
    guint len;
    setup_test();

    len = make_pkt_mpls(test_buffer, 0x1, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP, 1);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_mpls(test_buffer, 0x2, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP, 2);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_mpls(test_buffer, 0x3, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6, 1);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_mpls(test_buffer, 0x4, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6, 2);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_ipv6_ext()
{
    setup_test();

    guint len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HBH_OPT, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_DEST_OPT, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ROUTING, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_MOBILITY, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_HIPV2, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SHIM6, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_FRAGMENT, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_AUTH, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_SCTP, TRUE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV4, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_IPV6, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_ESP, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_ipv6_ext(test_buffer, IP_PROTOCOL_NO_NEXT_HDR, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_gre()
{
    guint len;
    setup_test();

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_ICMP);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_PPPOE_SESS, IP_PROTOCOL_ICMP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_ICMPV6);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_PPPOE_SESS, IP_PROTOCOL_ICMPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);
}

void test_flow_parse_gre_no_tunnel_inspection()
{
    guint len;
    setup_test();

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);

    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMPV6);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
    g_assert(inet_tuple_get_protocol(test_tuple) == IP_PROTOCOL_GRE);
}

void test_flow_parse_unsupported_eth_protocols()
{
    setup_test();

    /* ARP */
    guint len = make_pkt(test_buffer, 0x0806, IP_PROTOCOL_ICMP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* AARP */
    len = make_pkt(test_buffer, 0x80F3, IP_PROTOCOL_ICMP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* IPX */
    len = make_pkt(test_buffer, 0x8137, IP_PROTOCOL_ICMP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* PPPoE Discovery */
    len = make_pkt(test_buffer, 0x8863, IP_PROTOCOL_ICMP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_not_ipv6_ext()
{
    setup_test();

    /* KRYPTOLAN */
    guint len = make_pkt_ipv6_ext(test_buffer, 65, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));

    /* IGMP */
    len = make_pkt_ipv6_ext(test_buffer, 2, FALSE);
    g_assert(parse_ipv6_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_unsupported_transport_protocols()
{
    setup_test();

    /* CRUDP */
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 127);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* UDPLite */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, 136);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* IL */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, 40);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_sctp_ipv4()
{
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_SCTP);
    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
    g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, IP_PROTOCOL_SCTP);
    g_assert_cmpuint(inet_tuple_get_src_port(test_tuple), ==, TEST_SPORT);
    g_assert_cmpuint(inet_tuple_get_dst_port(test_tuple), ==, TEST_DPORT);

    /* The frame ends inside the SCTP header */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 1, FALSE));
}

void test_flow_parse_unsupported_ppp_protocols()
{
    setup_test();

    /* IPCP */
    guint len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8021);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* ATCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x8029);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* IPXCP */
    len = make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, 0x802B);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_more_than_2_vlan_tags()
{
    setup_test();

    guint len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IP, ETH_PROTOCOL_8021Q, IP_PROTOCOL_ICMP,
                              3);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    len = make_pkt_vlan(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_8021AD, IP_PROTOCOL_ICMPV6, 3);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));
}

void test_flow_parse_malformed_vlan_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_8021Q);
    p = build_hdr_vlan(p, ETH_PROTOCOL_8021Q, ETH_PROTOCOL_IP, 1);
    guint8 len = (guint) (p - test_buffer);

    /* No VLAN length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(vlan_hdr_t), TRUE));
    /* Partial VLAN length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 1, FALSE));
}

void test_flow_parse_malformed_ipv4_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip(p, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No IPv4 length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(ip_hdr_t), FALSE));
    /* Partial IPv4 length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 8, FALSE));
}

void test_flow_parse_ipv4_options()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ipv4_options(p, IP_PROTOCOL_TCP, 8);
    p = build_hdr_tcp(p, FALSE);
    guint len = (guint) (p - test_buffer);

    g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
    g_assert_cmpuint(test_tuple->sport, ==, htons(TEST_SPORT));
    g_assert_cmpuint(test_tuple->dport, ==, htons(TEST_DPORT));
    g_assert_cmpuint(test_tuple->offset, ==, sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t) + 8);
}

void test_flow_parse_malformed_ipv4_hlen()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    ip_hdr_t *ip = (ip_hdr_t *) p;
    p = build_hdr_ipv4_options(p, IP_PROTOCOL_TCP, 8);
    p = build_hdr_tcp(p, FALSE);
    guint len = (guint) (p - test_buffer);

    /* Header length shorter than the fixed IPv4 header */
    ip->ihl_version = 0x44;
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* Header length longer than the packet */
    ip->ihl_version = 0x4f;
    g_assert_false(parse_tuple(test_tuple, test_buffer, sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t) + 8, FALSE));
}

void test_flow_parse_malformed_ipv6_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No IPv6 length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(ip6_hdr_t), FALSE));
    /* Partial IPv6 length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 8, FALSE));
}

void test_flow_parse_malformed_pppoe_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_PPPOE_SESS);
    p = build_hdr_pppoe(p, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No PPPoE length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(pppoe_sess_hdr_t), FALSE));
    /* Partial PPPoE length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 2, FALSE));
}

void test_flow_parse_malformed_tcp_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No TCP length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(tcp_hdr_t), TRUE));
    /* Partial TCP length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, TRUE));
}

void test_flow_parse_malformed_udp_hdr_length()
{
    setup_test();

    guint8 *p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_UDP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No UDP length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - sizeof(udp_hdr_t), FALSE));
    /* Partial UDP length */
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, FALSE));
}

void test_flow_parse_malformed_icmp_hdr_length()
{
    setup_test();

    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);

    /* No ICMP length */
    g_assert(parse_tuple(test_tuple, test_buffer, len - sizeof(icmp_hdr_t), FALSE));
    /* Partial ICMP length */
    g_assert(parse_tuple(test_tuple, test_buffer, len - 4, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_hbh_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_HBH_OPT, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_HBH_OPT, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No HBH header length ( (4 + 1) * 8) */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 40, FALSE));
    /* Partial part HBH header length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 39, FALSE));
    /* Partial full HBH length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 8, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_frag_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_FRAGMENT, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_FRAGMENT, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No Fragment header length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - sizeof(frag_hdr_t), FALSE));
    /* Partial Fragment length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 4, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_auth_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_AUTH, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_AUTH, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No Auth length ( (4 + 2) * 4) */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 24, FALSE));
    /* Partial part Auth header length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 23, FALSE));
    /* Partial full Auth length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 8, FALSE));
}

void test_flow_parse_malformed_ipv6_ext_sctp_length()
{
    setup_test();

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_SCTP, FALSE);
    p = build_hdr_ipv6_ext(p, IP_PROTOCOL_SCTP, IP_PROTOCOL_ICMP, FALSE);
    guint len = (guint) (p - test_buffer);

    /* No SCTP length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, sizeof(sctp_hdr_t), FALSE));
    /* Partial SCTP length */
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, len - 8, FALSE));
}

gchar *num_to_string(guint8 * number, int family)
{
    char str[INET6_ADDRSTRLEN];
    if (inet_ntop(family, number, str, INET6_ADDRSTRLEN) == NULL) {
        return NULL;
    }
    return g_strdup(str);
}

void test_flow_properties()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();

    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    g_assert_cmpuint(flow->packets, ==, 2);
    g_assert(FLOW_PRIV(flow)->hash);
    g_assert_cmpuint(inet_flow_protocol(flow), ==, IP_PROTOCOL_TCP);


    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_client_port(&flow->tuple), ==, htons(TEST_DPORT));

    g_assert(inet_tuple_server_addr(&flow->tuple)->v4.s_addr == htonl(TEST_SADDR));
    g_assert(inet_tuple_server_addr(&flow->tuple)->v4.s_addr == htonl(TEST_SADDR));
    g_assert(inet_tuple_client_addr(&flow->tuple)->v4.s_addr == htonl(TEST_DADDR));

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_properties_reversed()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();

    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    /* Update flow */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    g_assert_cmpuint(flow->packets, ==, 2);
    g_assert(FLOW_PRIV(flow)->hash);
    g_assert_cmpuint(inet_flow_protocol(flow), ==, IP_PROTOCOL_TCP);


    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_client_port(&flow->tuple), ==, htons(TEST_DPORT));

    g_assert(inet_tuple_server_addr(&flow->tuple)->v4.s_addr == htonl(TEST_SADDR));
    g_assert(inet_tuple_server_addr(&flow->tuple)->v4.s_addr == htonl(TEST_SADDR));
    g_assert(inet_tuple_client_addr(&flow->tuple)->v4.s_addr == htonl(TEST_DADDR));

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_properties_ipv6()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();

    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    g_assert_cmpuint(flow->packets, ==, 2);
    g_assert(FLOW_PRIV(flow)->hash);
    g_assert_cmpuint(inet_flow_protocol(flow), ==, IP_PROTOCOL_TCP);


    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_client_port(&flow->tuple), ==, htons(TEST_DPORT));

    g_assert(memcmp(inet_tuple_server_addr(&flow->tuple), test_ip6src, sizeof(test_ip6src)) == 0);
    g_assert(memcmp(inet_tuple_server_addr(&flow->tuple), test_ip6src, sizeof(test_ip6src)) == 0);
    g_assert(memcmp(inet_tuple_client_addr(&flow->tuple), test_ip6dst, sizeof(test_ip6dst)) == 0);

    inet_flow_free(flow);
    inet_flow_table_free(table);
}


void test_flow_properties_ipv6_reversed()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();

    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    /* Update flow */
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    g_assert_cmpuint(flow->packets, ==, 2);
    g_assert(FLOW_PRIV(flow)->hash);
    g_assert_cmpuint(inet_flow_protocol(flow), ==, IP_PROTOCOL_TCP);


    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_server_port(&flow->tuple), ==, htons(TEST_SPORT));
    g_assert_cmpuint(inet_tuple_client_port(&flow->tuple), ==, htons(TEST_DPORT));

    g_assert(memcmp(inet_tuple_server_addr(&flow->tuple), test_ip6src, sizeof(test_ip6src)) == 0);
    g_assert(memcmp(inet_tuple_server_addr(&flow->tuple), test_ip6src, sizeof(test_ip6src)) == 0);
    g_assert(memcmp(inet_tuple_client_addr(&flow->tuple), test_ip6dst, sizeof(test_ip6dst)) == 0);

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_table_properties()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    g_assert_cmpuint(inet_flow_table_size(table), ==, 2);
    g_assert_cmpuint(table->hits, ==, 1);
    g_assert_cmpuint(table->misses, ==, 2);

    inet_flow_free(flow1);
    inet_flow_free(flow2);
    inet_flow_table_free(table);
}

void flow_print_protocol(InetFlow * flow)
{
    guint protocol;

    g_assert_nonnull(flow);
    g_assert((inet_flow_protocol(flow) == IP_PROTOCOL_TCP) || (inet_flow_protocol(flow) == IP_PROTOCOL_UDP));
    g_assert_nonnull(inet_tuple_server_addr(&flow->tuple));
}

void test_flow_foreach()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    inet_flow_foreach(table, (IFFunc) flow_print_protocol, NULL);

    inet_flow_free(flow1);
    inet_flow_free(flow2);
    inet_flow_table_free(table);
}

void test_flow_create()
{
    InetFlowTable *table = inet_flow_table_new();
    guint64 now = get_time_us();
    setup_test();
    g_assert_nonnull(table);
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    InetFlow *flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL);
    g_assert_nonnull(flow);
    guint64 size;
    g_assert_cmpint(inet_flow_table_size(table), ==, 1);
    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_create_many()
{
    InetFlowTable *table = inet_flow_table_new();
    guint64 now = get_time_us();
    setup_test();
    g_assert_nonnull(table);
    for (int i = 0; i < 10000; i++) {
        udp_hdr_t *udp = (udp_hdr_t *) build_hdr_ipv4(test_buffer, IP_PROTOCOL_UDP, FALSE);
        udp->source = htons(TEST_SPORT + i);
        udp->destination = htons(TEST_DPORT);
        udp->length = 0x0020;
        udp->check = 0x0000;
        guint len = (guint) ((void *)udp - (void *)test_buffer) + 0x0020;
        InetFlow *flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET_IP, NULL);
        g_assert_nonnull(flow);
    }
    g_assert_cmpint(inet_flow_table_size(table), ==, 10000);
    inet_flow_table_free(table);
}

void test_flow_table_size()
{
    InetFlowTable *table = inet_flow_table_new();
    setup_test();
    g_assert_nonnull(table);

    guint64 max;
    g_assert_cmpint(table->max, ==, 0);

    inet_flow_table_max_set(table, 1);
    g_assert_cmpint(table->max, ==, 1);

    guint pk1 = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    InetFlow *flow1 = inet_flow_get(table, test_buffer, pk1, get_time_us(), FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    guint pk2 = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    InetFlow *flow2 = inet_flow_get(table, test_buffer, pk2, get_time_us(), FLOW_GET, NULL);
    g_assert_null(flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_not_expired()
{
    guint64 now = get_time_us();
    guint64 later = now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000) - 1;
    InetFlowTable *table;
    InetFlow *flow;
    guint64 size;

    setup_test();
    g_assert_nonnull(table = inet_flow_table_new());
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL);
    g_assert_null(inet_flow_expire(table, later));
    g_assert_cmpint(inet_flow_table_size(table), ==, 1);
    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_expired()
{
    guint64 now = get_time_us();
    guint64 later = now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    InetFlowTable *table;
    InetFlow *flow;
    guint64 size;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL);
    g_assert_nonnull(inet_flow_expire(table, later));
    inet_flow_free(flow);
    g_assert_null(inet_flow_expire(table, later));
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);
    inet_flow_table_free(table);
}

void test_flow_expired_no_unref()
{
    guint64 now = get_time_us();
    guint64 later = now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL);
    g_assert_nonnull(inet_flow_expire(table, later));
    g_assert_nonnull(inet_flow_expire(table, later));
    g_assert_nonnull(inet_flow_expire(table, later));
    inet_flow_free(flow);
    g_assert_null(inet_flow_expire(table, later));
    inet_flow_table_free(table);
}

void test_flow_expired_only_once()
{
    guint64 now = get_time_us();
    guint64 later = now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL);
    while ((flow = inet_flow_expire(table, later))) {
        inet_flow_free(flow);
    }
    inet_flow_table_free(table);
}

void test_flow_tcp_new()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_tcp_update()
{
    InetFlowTable *table;
    InetFlow *flow;
    guint state = FLOW_CLOSED;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    guint len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    /* Update flow */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));

    /* Flow not updated */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, INET_FLOW_L2, NULL)));

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

guint8 *build_pkt_tcp(guint8 * buffer,
                      guint16 eth_protocol, guint ip_protocol, gboolean reverse, guint16 sport, guint16 dport, guint16 flags)
{
    guint8 *p = build_hdr_eth(buffer, eth_protocol);
    p = build_hdr_ip(p, eth_protocol, ip_protocol, reverse);
    p = build_hdr_tcp_detail(p, sport, dport, flags);
    return p;
}

void test_flow_tcp_state_basic()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);

    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 1, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 2, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* Outgoing TCP FIN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, FIN_ACK);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 3, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_CLOSED);
    inet_flow_expire(table, flow->timestamp + (INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_syn_rst()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 1, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_CLOSED);
    inet_flow_expire(table, flow->timestamp + (INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_syn_synack_rst()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 1, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 2, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_CLOSED);
    inet_flow_expire(table, flow->timestamp + (INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_fin_rst()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 1, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 2, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* TCP RST Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, RST);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 3, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_CLOSED);
    inet_flow_expire(table, flow->timestamp + (INET_FLOW_DEFAULT_CLOSED_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_syn_timeout()
{
    guint64 now = get_time_us();
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);

    /* Set packet timestamp */
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);
    inet_flow_expire(table, now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_syn_synack_timeout()
{
    guint64 now = get_time_us();
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);

    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    /* Set packet timestamp */
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);
    inet_flow_expire(table, now + (INET_FLOW_DEFAULT_OPEN_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_tcp_state_fin_timeout()
{
    guint64 now = get_time_us();
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Incoming TCP SYN Packet */
    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* Outgoing TCP SYN-ACK Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, TRUE, TEST_DPORT, TEST_SPORT, SYN_ACK);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 1, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    /* Incoming TCP FIN Packet */
    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, TEST_SPORT, TEST_DPORT, FIN);
    len = (guint) (p - test_buffer);
    /* Set packet timestamp */
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL)));
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);

    inet_flow_expire(table, now + (INET_FLOW_DEFAULT_OPEN_TIMEOUT * 1000000));
    inet_flow_free(flow);

    /* Always expect flow to expire when it is closed */
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    inet_flow_table_free(table);
}

void test_flow_ipv4_encap()
{
    InetFlowTable *table;
    InetFlow *flow;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET_IP, NULL)));
    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_ipv6_encap()
{
    InetFlow *flow;
    InetFlowTable *table;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    guint8 *p = build_hdr_ip(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET_IP, NULL)));

    inet_flow_free(flow);
    inet_flow_table_free(table);
}

void test_flow_bad_ip_version()
{
    setup_test();

    guint8 *p = build_hdr_bad_ipv4(test_buffer, IP_PROTOCOL_TCP, FALSE);
    p = build_hdr_after_ip(p, IP_PROTOCOL_TCP, FALSE);
    guint len = (guint) (p - test_buffer);

    g_assert_false(inet_packet_parse(test_buffer, len, INET_FLOW_TUNNEL, NULL, &test_packet));
}

void test_flow_parse_ipv4_fragment()
{
    guint8 *p;
    InetFlow *flow1, *flow2, *flow3;
    InetFlowTable *table;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);

    /* First IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    guint8 len = (guint) (p - test_buffer);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* Second IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 1, 0xbeef);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(flow1 == flow2);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* Last IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, FALSE, 2, 0xbeef);
    g_assert_nonnull((flow3 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(flow1 == flow3);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_table_free_fragments()
{
    InetFlowTable *table;
    guint8 *p;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Free the table while it still holds the first fragment of a datagram */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    g_assert_nonnull(inet_flow_get(table, test_buffer, (guint) (p - test_buffer), 0, FLOW_GET, NULL));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);
    inet_flow_table_free(table);
}

void test_flow_fragment_direction(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlow *first, *last;
    InetFlowTable *table;
    guint8 *p;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* First fragment from the client */
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((first = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* The last fragment of a datagram from the server with the same ID */
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, TRUE, FALSE, 1, 0xbeef);
    len = (guint) (p - test_buffer);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 2);

    /* The last fragment from the client still finds the first fragment */
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, FALSE, 1, 0xbeef);
    len = (guint) (p - test_buffer);
    g_assert_nonnull((last = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(first == last);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);
    inet_flow_table_free(table);
}

void test_flow_parse_ipv6_fragment()
{
    guint8 *p;
    InetFlow *flow1, *flow2, *flow3;
    InetFlowTable *table;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);

    /* First IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    guint8 len = (guint) (p - test_buffer);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* Second IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, TRUE, 1, 0xbeef);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(flow1 == flow2);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* Last IP fragment */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, FALSE, 2, 0xbeef);
    g_assert_nonnull((flow3 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    g_assert(flow1 == flow3);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_clear_expired_frag_info()
{
    guint8 *p;
    InetFlow *flow1, *flow2, *flow3;
    InetFlowTable *table;
    /* The fragments are up to 50 s older than now, and the monotonic clock
     * reads less than that on a machine that has just booted */
    guint64 now = 100 * TIMESTAMP_RESOLUTION_US;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);

    /* IP fragment 1 - expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x1111);
    guint8 len = (guint) (p - test_buffer);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, now - 50 * 1000000, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* IP fragment 2 - expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x2222);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, now - 40 * 1000000, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 2);

    /* IP fragment 3 - not expired */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0x3333);
    g_assert_nonnull((flow3 = inet_flow_get(table, test_buffer, len, now - 30 * 1000000, FLOW_GET, NULL)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 3);

    g_assert(clear_expired_frag_info(table->frag_info_list, now) == 2);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    InetFragment *non_expired = table->frag_info_list->age.head->data;
    g_assert(non_expired->id == 0x3333);

    /* Do proper clean up */
    clear_expired_frag_info(table->frag_info_list, now + 1000000);
    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_expiry_queue()
{
    guint64 now = get_time_us();
    guint64 later = (now * 10) + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);
    guint64 timeout = now + (INET_FLOW_DEFAULT_NEW_TIMEOUT * 1000000);

    InetFlowTable *table;
    guint64 size;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    guint8 *p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE,
                              TEST_SPORT, TEST_DPORT, SYN);
    guint len1 = (guint) (p - test_buffer);

    InetFlow *flow1 = inet_flow_get(table, test_buffer, len1, now, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    p = build_pkt_tcp(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE, 0x1238, 0x5678, SYN);
    guint len2 = (guint) (p - test_buffer);
    InetFlow *flow2 = inet_flow_get(table, test_buffer, len2, later, FLOW_GET, NULL);

    g_assert_nonnull(inet_flow_expire(table, timeout));
    inet_flow_free(flow1);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);
    inet_flow_free(flow2);
    inet_flow_table_free(table);
}

void test_flow_match_udp()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_match_same_ports(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    /* Both ends use the same port, as for IKE on port 500 */
    TEST_DPORT = TEST_SPORT;
    len = make_pkt(test_buffer, eth_protocol, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    len = make_pkt_reverse(test_buffer, eth_protocol, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    TEST_DPORT = _TEST_DPORT;

    g_assert(flow1 == flow2);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);
    inet_flow_table_free(table);
}

static void set_tuple(InetTuple * tuple, int family, guint16 sport, guint16 dport)
{
    memset(tuple, 0, sizeof(*tuple));
    tuple->protocol = IP_PROTOCOL_UDP;
    tuple->family = family;
    tuple->sport = g_htons(sport);
    tuple->dport = g_htons(dport);
}

void test_tuple_equal_family()
{
    InetTuple v4, v6;

    /* All zero addresses compare equal byte for byte across the families */
    set_tuple(&v4, AF_INET, 68, 67);
    set_tuple(&v6, AF_INET6, 68, 67);
    g_assert_false(inet_tuple_equal(&v4, &v6));
    g_assert_false(inet_tuple_equal(&v6, &v4));
    g_assert_true(inet_tuple_equal(&v4, &v4));
    g_assert_true(inet_tuple_equal(&v6, &v6));
}

void test_flow_match_udp6()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_match_tcp()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_match_tcp6()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_TCP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_match_icmp()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_match_icmp6()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_ICMP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow2);

    g_assert(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_table_free(table);
}

void test_flow_nomatch_port()
{
    InetFlowTable *table;
    InetFlow *flow1, *flow2;
    guint len;

    setup_test();
    g_assert_nonnull((table = inet_flow_table_new()));

    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow1 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    g_assert_nonnull(flow1);

    /* Will match the same hash bucket */
    TEST_SPORT = _TEST_SPORT - 1;
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    flow2 = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL);
    TEST_SPORT = _TEST_SPORT;
    g_assert_nonnull(flow2);

    g_assert_false(flow1 == flow2);

    inet_flow_free(flow1);
    inet_flow_free(flow2);
    inet_flow_table_free(table);
}

void test_tuple_exact()
{
    InetTuple a, b;

    setup_test();
    make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(&a, test_buffer, MAX_BUFFER_SIZE, FALSE));
    b = a;
    g_assert_true(inet_tuple_exact(&a, &b));

    /* The same addresses in the other direction */
    make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    memset(&b, 0, sizeof(b));
    g_assert(parse_tuple(&b, test_buffer, MAX_BUFFER_SIZE, FALSE));
    g_assert_false(inet_tuple_exact(&a, &b));
    g_assert_true(inet_tuple_equal(&a, &b));

    /* Another protocol */
    b = a;
    b.protocol = IP_PROTOCOL_TCP;
    g_assert_false(inet_tuple_exact(&a, &b));

    /* Another destination address */
    b = a;
    b.dst.v4.s_addr ^= 1;
    g_assert_false(inet_tuple_exact(&a, &b));
}

/* Build an IPv4 GRE frame with the given GRE flags and an inner UDP packet */
static guint make_pkt_gre_flags(guint8 * buffer, guint16 gre_flags, guint16 inner_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip(p, ETH_PROTOCOL_IP, IP_PROTOCOL_GRE, FALSE);
    gre_hdr_t *gre = (gre_hdr_t *) p;
    p = build_hdr_gre(p, inner_protocol, FALSE);
    gre->flags_version = g_htons(gre_flags);
    /* Checksum and offset, key, and sequence number words */
    memset(p, 0xff, 12);
    p += ((gre_flags & (GRE_HEADER_CSUM | GRE_HEADER_ROUTING)) ? 4 : 0) +
        ((gre_flags & GRE_HEADER_KEY) ? 4 : 0) + ((gre_flags & GRE_HEADER_SEQ) ? 4 : 0);
    p = build_hdr_ip(p, inner_protocol, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_udp(p, FALSE);
    return (guint) (p - buffer);
}

void test_flow_parse_gre_options()
{
    guint16 flags[] = { GRE_HEADER_CSUM, GRE_HEADER_KEY, GRE_HEADER_SEQ,
        GRE_HEADER_CSUM | GRE_HEADER_KEY | GRE_HEADER_SEQ
    };
    guint16 protocols[] = { ETH_PROTOCOL_IP, ETH_PROTOCOL_IPV6 };
    guint len;
    int i, j;

    for (i = 0; i < G_N_ELEMENTS(flags); i++) {
        for (j = 0; j < G_N_ELEMENTS(protocols); j++) {
            setup_test();
            len = make_pkt_gre_flags(test_buffer, flags[i], protocols[j]);
            g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
            g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, IP_PROTOCOL_UDP);
            g_assert_cmpuint(test_tuple->sport, ==, htons(TEST_SPORT));

            /* The inner packet ends inside its transport header */
            g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, TRUE));
        }
    }
}

/* Build an IPv6 frame that carries an IPv4 or IPv6 packet */
static guint make_pkt_in_ipv6(guint8 * buffer, guint inner_ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ipv6(p, inner_ip_protocol, FALSE);
    if (inner_ip_protocol == IP_PROTOCOL_IPV4)
        p = build_hdr_ipv4(p, IP_PROTOCOL_UDP, FALSE);
    else
        p = build_hdr_ipv6(p, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_udp(p, FALSE);
    return (guint) (p - buffer);
}

static guint make_pkt_in_ipv4(guint8 * buffer, guint inner_ip_protocol)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ipv4(p, inner_ip_protocol, FALSE);
    if (inner_ip_protocol == IP_PROTOCOL_IPV4)
        p = build_hdr_ipv4(p, IP_PROTOCOL_UDP, FALSE);
    else
        p = build_hdr_ipv6(p, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_udp(p, FALSE);
    return (guint) (p - buffer);
}

void test_flow_parse_ip_in_ipv4()
{
    guint inner[] = { IP_PROTOCOL_IPV4, IP_PROTOCOL_IPV6 };
    guint len;
    int i;

    for (i = 0; i < G_N_ELEMENTS(inner); i++) {
        setup_test();
        len = make_pkt_in_ipv4(test_buffer, inner[i]);

        /* With tunnel inspection the tuple is the inner packet */
        g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
        g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, IP_PROTOCOL_UDP);
        g_assert_cmpuint(inet_tuple_family(test_tuple), ==, inner[i] == IP_PROTOCOL_IPV4 ? AF_INET : AF_INET6);
        g_assert_cmpuint(inet_tuple_get_dst_port(test_tuple), ==, htons(TEST_DPORT));

        /* The inner packet ends inside its transport header */
        g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, TRUE));

        /* Without tunnel inspection the tuple is the outer packet */
        memset(test_tuple, 0, sizeof(*test_tuple));
        g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
        g_assert_cmpuint(inet_tuple_family(test_tuple), ==, AF_INET);
        g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, inner[i]);
        g_assert_cmpuint(inet_tuple_get_dst_port(test_tuple), ==, 0);
    }
}

void test_flow_parse_ip_in_ipv6()
{
    guint inner[] = { IP_PROTOCOL_IPV4, IP_PROTOCOL_IPV6 };
    guint len;
    int i;

    for (i = 0; i < G_N_ELEMENTS(inner); i++) {
        setup_test();
        len = make_pkt_in_ipv6(test_buffer, inner[i]);

        /* With tunnel inspection the tuple is the inner packet */
        g_assert(parse_tuple(test_tuple, test_buffer, len, TRUE));
        g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, IP_PROTOCOL_UDP);
        g_assert_cmpuint(inet_tuple_family(test_tuple), ==, inner[i] == IP_PROTOCOL_IPV4 ? AF_INET : AF_INET6);

        /* The inner packet ends inside its transport header */
        g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, TRUE));

        /* Without tunnel inspection the tuple is the outer packet */
        memset(test_tuple, 0, sizeof(*test_tuple));
        g_assert(parse_tuple(test_tuple, test_buffer, len, FALSE));
        g_assert_cmpuint(inet_tuple_get_protocol(test_tuple), ==, inner[i]);
    }
}

/* Build levels of IPv6 in IPv6 headers followed by a UDP header */
static guint build_nested_ipv6(guint8 * buf, guint levels)
{
    guint len = levels * sizeof(ip6_hdr_t) + sizeof(udp_hdr_t);
    guint i;

    memset(buf, 0, len);
    for (i = 0; i < levels; i++) {
        ip6_hdr_t *ip6 = (ip6_hdr_t *) (buf + i * sizeof(ip6_hdr_t));
        ip6->ver_tc_fl = htonl(0x60000000);
        ip6->pay_len = htons(len - (i + 1) * sizeof(ip6_hdr_t));
        ip6->next_hdr = i + 1 < levels ? IP_PROTOCOL_IPV6 : IP_PROTOCOL_UDP;
        ip6->saddr[15] = 1;
        ip6->daddr[15] = 2;
    }
    udp_hdr_t *udp = (udp_hdr_t *) (buf + levels * sizeof(ip6_hdr_t));
    udp->source = htons(TEST_SPORT);
    udp->destination = htons(TEST_DPORT);
    udp->length = htons(sizeof(udp_hdr_t));
    return len;
}

static gpointer parse_deep_tunnel(gpointer data)
{
    guint8 *buf = g_malloc(G_MAXUINT16);
    guint len = build_nested_ipv6(buf, (G_MAXUINT16 - sizeof(udp_hdr_t)) / sizeof(ip6_hdr_t));
    InetPacket *pkt = data;

    inet_packet_parse(buf, len, INET_FLOW_TUNNEL, NULL, pkt);
    g_free(buf);
    return NULL;
}

void test_flow_parse_tunnel_depth()
{
    guint8 buf[1024];
    pthread_attr_t attr;
    pthread_t thread;
    InetPacket pkt;
    guint len;

    /* Eight IP headers parse to the innermost packet */
    len = build_nested_ipv6(buf, MAX_IP_DEPTH);
    g_assert_true(inet_packet_parse(buf, len, INET_FLOW_TUNNEL, NULL, &pkt));
    g_assert_cmpuint(pkt.tuple.dport, ==, htons(TEST_DPORT));
    g_assert_cmpuint(pkt.anomalies, ==, 0);

    /* A ninth fails the parse */
    len = build_nested_ipv6(buf, MAX_IP_DEPTH + 1);
    g_assert_false(inet_packet_parse(buf, len, INET_FLOW_TUNNEL, NULL, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_PARSE_ERROR);
    g_assert_cmpuint(pkt.anomalies, ==, INET_ANOMALY_TUNNEL_DEPTH);

    /* Without tunnel inspection only the outer header is parsed */
    g_assert_true(inet_packet_parse(buf, len, 0, NULL, &pkt));
    g_assert_cmpuint(pkt.tuple.protocol, ==, IP_PROTOCOL_IPV6);

    /* A 64 KiB frame of nested headers fits in a 64 KiB thread stack */
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 64 * 1024);
    g_assert_cmpint(pthread_create(&thread, &attr, parse_deep_tunnel, &pkt), ==, 0);
    pthread_join(thread, NULL);
    pthread_attr_destroy(&attr);
    g_assert_cmpuint(pkt.anomalies, ==, INET_ANOMALY_TUNNEL_DEPTH);
}

void test_flow_parse_tunnel_depth_gre()
{
    guint8 buf[1024];
    guint8 *p = buf;
    InetPacket pkt;
    guint i, levels = MAX_IP_DEPTH + 1;
    guint len = levels * (sizeof(ip_hdr_t) + sizeof(gre_hdr_t));

    /* IPv4 and GRE headers nested past the limit */
    memset(buf, 0, sizeof(buf));
    for (i = 0; i < levels; i++) {
        ip_hdr_t *ip = (ip_hdr_t *) p;
        gre_hdr_t *gre = (gre_hdr_t *) (p + sizeof(ip_hdr_t));
        ip->ihl_version = 0x45;
        ip->tot_len = htons(len - i * (sizeof(ip_hdr_t) + sizeof(gre_hdr_t)));
        ip->protocol = IP_PROTOCOL_GRE;
        gre->protocol = htons(ETH_PROTOCOL_IP);
        p += sizeof(ip_hdr_t) + sizeof(gre_hdr_t);
    }
    g_assert_false(inet_packet_parse(buf, len, INET_FLOW_TUNNEL, NULL, &pkt));
    g_assert_cmpuint(pkt.anomalies & INET_ANOMALY_TUNNEL_DEPTH, !=, 0);
}

void test_packet_l3()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));

    /* With tunnel inspection the header is the inner IP header */
    len = make_pkt_gre(test_buffer, ETH_PROTOCOL_IPV6, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET | INET_FLOW_TUNNEL, &pkt));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t) + sizeof(ip6_hdr_t) + sizeof(gre_hdr_t));
    inet_flow_table_free(table);
}

void test_packet_tuple()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt)));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_OK);
    g_assert_true(inet_tuple_exact(&pkt.tuple, &flow->tuple));

    /* A frame that does not parse */
    g_assert_null(inet_flow_get(table, test_buffer, 10, 0, FLOW_GET, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_PARSE_ERROR);
    inet_flow_table_free(table);
}

void test_flow_get_full_parse_fail()
{
    InetFlowTable *table = inet_flow_table_new();
    guint len;

    setup_test();
    /* An Ethernet frame that does not carry IP */
    len = make_pkt(test_buffer, 0x0806, IP_PROTOCOL_UDP);
    g_assert_null(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));

    /* An IP packet with an unknown version */
    guint8 *p = build_hdr_bad_ipv4(test_buffer, IP_PROTOCOL_UDP, FALSE);
    p = build_hdr_udp(p, FALSE);
    g_assert_null(inet_flow_get(table, test_buffer, (guint) (p - test_buffer), 0, FLOW_GET_IP, NULL));
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);
    inet_flow_table_free(table);
}

void test_packet_parse()
{
    InetPacket pkt;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);

    /* A frame starting with Ethernet */
    g_assert_true(inet_packet_parse(test_buffer, len, INET_FLOW_L2, NULL, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_OK);
    g_assert_cmpuint(pkt.tuple.sport, ==, htons(TEST_SPORT));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));

    /* A packet starting with IP */
    g_assert_true(inet_packet_parse(test_buffer + sizeof(ethernet_hdr_t), len - sizeof(ethernet_hdr_t), 0, NULL, &pkt));
    g_assert_cmpuint(pkt.tuple.dport, ==, htons(TEST_DPORT));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));

    /* An Ethernet frame parsed as IP */
    g_assert_false(inet_packet_parse(test_buffer, len, 0, NULL, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_PARSE_ERROR);
}

void test_flow_create_lookup()
{
    InetFlowTable *table = inet_flow_table_new();
    InetTuple tuple = { 0 };
    InetTuple other;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_true(parse_tuple(&tuple, test_buffer, len, FALSE));

    g_assert_null(inet_flow_lookup(table, &tuple));
    inet_flow_table_max_set(table, 2);
    g_assert_nonnull((flow = inet_flow_create(table, &tuple, 1000)));
    g_assert(inet_flow_lookup(table, &tuple) == flow);
    g_assert_cmpuint(flow->state, ==, FLOW_NEW);
    g_assert_cmpuint(flow->timestamp, ==, 1000);

    /* A packet of the flow finds the created flow */
    g_assert(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)
             == flow);

    /* No flow is created when the table is full */
    inet_flow_table_max_set(table, 1);
    other = tuple;
    other.sport = htons(1);
    g_assert_null(inet_flow_create(table, &other, 0));
    g_assert_null(inet_flow_lookup(table, &other));
    inet_flow_table_free(table);
}

void test_flow_create_existing()
{
    InetFlowTable *table = inet_flow_table_new();
    InetTuple tuple = { 0 };
    InetTuple reversed;
    InetFlow *flow;
    guint len;

    setup_test();
    inet_flow_table_context_free_set(table, g_free);
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_true(parse_tuple(&tuple, test_buffer, len, FALSE));
    g_assert_nonnull((flow = inet_flow_create(table, &tuple, 1000)));
    flow->context = g_strdup("context");

    /* Creating the flow again, in either direction, fails and leaves the existing flow unchanged */
    g_assert_null(inet_flow_create(table, &tuple, 2000));
    reversed = tuple;
    reversed.src = tuple.dst;
    reversed.dst = tuple.src;
    reversed.sport = tuple.dport;
    reversed.dport = tuple.sport;
    reversed.hash = 0;
    g_assert_null(inet_flow_create(table, &reversed, 3000));
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);
    g_assert(inet_flow_lookup(table, &tuple) == flow);
    g_assert_cmpuint(flow->timestamp, ==, 1000);
    g_assert_cmpstr(flow->context, ==, "context");
    inet_flow_table_free(table);
}

void test_flow_establish_close()
{
    InetFlowTable *table = inet_flow_table_new();
    guint64 ts = 1000;
    InetTuple tuple = { 0 };
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_true(parse_tuple(&tuple, test_buffer, len, FALSE));
    g_assert_nonnull((flow = inet_flow_create(table, &tuple, ts)));

    /* An established flow uses the open timeout */
    inet_flow_establish(table, flow);
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);
    g_assert_null(inet_flow_expire(table, ts + (INET_FLOW_DEFAULT_NEW_TIMEOUT + 1) * TIMESTAMP_RESOLUTION_US));
    g_assert(inet_flow_expire(table, ts + INET_FLOW_DEFAULT_OPEN_TIMEOUT * TIMESTAMP_RESOLUTION_US) == flow);

    /* A closed flow uses the closed timeout */
    inet_flow_close(table, flow);
    g_assert_cmpuint(flow->state, ==, FLOW_CLOSED);
    g_assert_null(inet_flow_expire(table, ts + (INET_FLOW_DEFAULT_CLOSED_TIMEOUT - 1) * TIMESTAMP_RESOLUTION_US));
    g_assert(inet_flow_expire(table, ts + INET_FLOW_DEFAULT_CLOSED_TIMEOUT * TIMESTAMP_RESOLUTION_US) == flow);
    inet_flow_table_free(table);
}

void test_flow_fragment_limit(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    guint64 now = get_time_us();
    guint8 *p;
    guint len;
    int i;

    setup_test();
    for (i = 0; i <= MAX_FRAG_DEPTH; i++) {
        p = build_hdr_eth(test_buffer, eth_protocol);
        p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, TRUE, 0, i);
        len = (guint) (p - test_buffer);
        if (i < MAX_FRAG_DEPTH) {
            g_assert_nonnull(inet_flow_get(table, test_buffer, len, now, FLOW_GET, NULL));
        } else {
            /* No more datagrams can be tracked */
            InetPacket pkt;
            g_assert_null(inet_flow_get(table, test_buffer, len, now, FLOW_GET, &pkt));
            g_assert_cmpint(pkt.status, ==, INET_PACKET_FRAG_UNTRACKED);
            g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_LIMIT, ==, INET_ANOMALY_FRAG_LIMIT);
        }
    }
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, MAX_FRAG_DEPTH);

    /* Expired datagrams make room for new ones */
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, now + (FRAG_EXPIRY_TIME + 1) * TIMESTAMP_RESOLUTION_US, FLOW_GET, NULL));
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 1);
    inet_flow_table_free(table);
}

void test_tuple_equal_mismatch()
{
    InetTuple a, b;

    setup_test();
    make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert(parse_tuple(&a, test_buffer, MAX_BUFFER_SIZE, FALSE));

    /* The upper end has the higher port, which is the destination */
    b = a;
    b.dst.v4.s_addr ^= 1;
    g_assert_false(inet_tuple_equal(&a, &b));
    b = a;
    b.dport = htons(TEST_DPORT + 1);
    g_assert_false(inet_tuple_equal(&a, &b));
}

void test_tuple_equal_directions()
{
    guint32 a = htonl(0x0a000001), b = htonl(0x0a000002), c = htonl(0x0a000003);
    InetTuple x, y;

    /* The same port at each end */
    inet_tuple_set(&x, AF_INET, IP_PROTOCOL_UDP, &a, htons(53), &b, htons(53));
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_UDP, &b, htons(53), &a, htons(53));
    g_assert_true(inet_tuple_equal(&x, &y));
    g_assert_true(inet_tuple_equal(&y, &x));
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_UDP, &a, htons(53), &c, htons(53));
    g_assert_false(inet_tuple_equal(&x, &y));

    /* The same hosts with the ports swapped are another flow */
    inet_tuple_set(&x, AF_INET, IP_PROTOCOL_TCP, &a, htons(1000), &b, htons(80));
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_TCP, &a, htons(80), &b, htons(1000));
    g_assert_false(inet_tuple_equal(&x, &y));
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_TCP, &b, htons(80), &a, htons(1000));
    g_assert_true(inet_tuple_equal(&x, &y));

    /* One end that matches is not enough */
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_TCP, &a, htons(1000), &c, htons(80));
    g_assert_false(inet_tuple_equal(&x, &y));
    inet_tuple_set(&y, AF_INET, IP_PROTOCOL_TCP, &c, htons(80), &a, htons(1000));
    g_assert_false(inet_tuple_equal(&x, &y));
}

void test_tuple_hash()
{
    guint32 src = htonl(0x0a000001), src2 = htonl(0x0a000002), dst = htonl(0x0b000001);
    struct in6_addr src6 = IN6ADDR_LOOPBACK_INIT;
    struct in6_addr dst6 = IN6ADDR_LOOPBACK_INIT;
    InetTuple a, b;

    dst6.s6_addr[15] = 2;

    /* Both directions of a flow have the same hash */
    inet_tuple_set(&a, AF_INET, IP_PROTOCOL_UDP, &src, htons(5000), &dst, htons(53));
    inet_tuple_set(&b, AF_INET, IP_PROTOCOL_UDP, &dst, htons(53), &src, htons(5000));
    g_assert_cmpuint(inet_tuple_hash(&a), ==, inet_tuple_hash(&b));
    inet_tuple_set(&a, AF_INET6, IP_PROTOCOL_TCP, &src6, htons(5000), &dst6, htons(80));
    inet_tuple_set(&b, AF_INET6, IP_PROTOCOL_TCP, &dst6, htons(80), &src6, htons(5000));
    g_assert_cmpuint(inet_tuple_hash(&a), ==, inet_tuple_hash(&b));

    /* Tuples without ports differ by address and protocol */
    inet_tuple_set(&a, AF_INET, IP_PROTOCOL_ICMP, &src, 0, &dst, 0);
    inet_tuple_set(&b, AF_INET, IP_PROTOCOL_ICMP, &src2, 0, &dst, 0);
    g_assert_cmpuint(inet_tuple_hash(&a), !=, inet_tuple_hash(&b));
    inet_tuple_set(&b, AF_INET, IP_PROTOCOL_ESP, &src, 0, &dst, 0);
    g_assert_cmpuint(inet_tuple_hash(&a), !=, inet_tuple_hash(&b));
}

/* Flows without ports must not share a hash bucket, or each lookup scans every such flow */
void test_table_hash_portless()
{
    InetFlowTable *table = inet_flow_table_new();
    GHashTable *hashes = g_hash_table_new(NULL, NULL);
    guint32 dst = htonl(0x0b000001);
    InetTuple tuple;
    InetFlow *flow;
    guint32 i, src;

    for (i = 0; i < 1000; i++) {
        src = htonl(0x0a000000 + i);
        inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_ICMP, &src, 0, &dst, 0);
        g_assert_nonnull((flow = inet_flow_create(table, &tuple, 1000)));
        g_hash_table_add(hashes, GUINT_TO_POINTER(FLOW_PRIV(flow)->hash));
    }
    g_assert_cmpuint(g_hash_table_size(hashes), >, 990);

    /* A packet in the reply direction finds the flow */
    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_ICMP, &dst, 0, &src, 0);
    g_assert(inet_flow_lookup(table, &tuple) == flow);
    g_hash_table_destroy(hashes);
    inet_flow_table_free(table);
}

/* The seed fixes the hash, so this runs in a new process that has not hashed
 * a flow. The expected values do not depend on the CPU or the system. */
void test_table_hash_seed()
{
    if (g_test_subprocess()) {
        guint32 a = htonl(0x0a000001), b = htonl(0xc0a80001);
        struct in6_addr a6 = IN6ADDR_LOOPBACK_INIT, b6 = IN6ADDR_LOOPBACK_INIT;
        InetFlowTable *table;
        InetTuple t, r;
        InetFlow *flow;

        b6.s6_addr[0] = 0x20;
        g_assert_true(inet_flow_hash_seed_set(42));
        g_assert_false(inet_flow_hash_seed_set(43));
        inet_tuple_set(&t, AF_INET, IP_PROTOCOL_TCP, &a, htons(40000), &b, htons(80));
        inet_tuple_set(&r, AF_INET, IP_PROTOCOL_TCP, &b, htons(80), &a, htons(40000));
        g_assert_cmphex(inet_tuple_hash(&t), ==, 0x8184660c);
        g_assert_cmphex(inet_tuple_hash(&r), ==, 0x8184660c);
        inet_tuple_set(&t, AF_INET6, IP_PROTOCOL_UDP, &a6, htons(5353), &b6, htons(53));
        inet_tuple_set(&r, AF_INET6, IP_PROTOCOL_UDP, &b6, htons(53), &a6, htons(5353));
        g_assert_cmphex(inet_tuple_hash(&t), ==, 0x7e4e4f5d);
        g_assert_cmphex(inet_tuple_hash(&r), ==, 0x7e4e4f5d);

        /* A table uses the same hash */
        table = inet_flow_table_new();
        t.hash = 0;
        g_assert_nonnull((flow = inet_flow_create(table, &t, 1000)));
        g_assert_cmphex(flow->tuple.hash, ==, 0x7e4e4f5d);
        inet_flow_table_free(table);
        return;
    }
    g_test_trap_subprocess(NULL, 0, 0);
    g_test_trap_assert_passed();

    /* Once a table has chosen the multipliers, the seed can not change them */
    inet_flow_table_free(inet_flow_table_new());
    g_assert_false(inet_flow_hash_seed_set(42));
}

/* inet_flow_get() stores the hash it computes in the packet and flow tuples,
 * and every table and inet_tuple_hash() compute the same hash */
void test_table_hash_stored()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlowTable *other = inet_flow_table_new();
    InetPacket pkt, reply;
    InetTuple copy;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt)));
    g_assert_cmpuint(pkt.tuple.hash, !=, 0);
    g_assert_cmpuint(flow->tuple.hash, ==, pkt.tuple.hash);
    g_assert_cmpuint(FLOW_PRIV(flow)->hash, ==, pkt.tuple.hash);
    copy = pkt.tuple;
    copy.hash = 0;
    g_assert_cmpuint(inet_tuple_hash(&copy), ==, pkt.tuple.hash);
    len = make_pkt_reverse(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &reply) == flow);
    g_assert_cmpuint(reply.tuple.hash, ==, pkt.tuple.hash);
    g_assert_nonnull((flow = inet_flow_get(other, test_buffer, len, 0, FLOW_GET, &reply)));
    g_assert_cmpuint(flow->tuple.hash, ==, pkt.tuple.hash);
    inet_flow_table_free(other);
    inet_flow_table_free(table);
}

static guint make_ipv6_fragment(guint8 * buffer, gboolean more_fragments, guint16 offset, guint16 id)
{
    guint8 *p = build_hdr_eth(buffer, ETH_PROTOCOL_IPV6);

    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP, FALSE, more_fragments, offset, id);
    return (guint) (p - buffer);
}

void test_flow_fragment_atomic()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint len;
    int i;

    setup_test();
    inet_flow_table_frag_limits_set(table, 2, 30);

    /* Atomic fragments are whole datagrams, so they do not fill the fragment list */
    for (i = 0; i < 4; i++) {
        len = make_ipv6_fragment(test_buffer, FALSE, 0, i);
        g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
        g_assert_false(pkt.fragment);
        g_assert_cmpuint(pkt.tuple.dport, ==, htons(TEST_DPORT));
        g_assert_nonnull(pkt.l4);
    }
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 0);

    /* An atomic fragment with the ID of a tracked datagram does not change it */
    len = make_ipv6_fragment(test_buffer, TRUE, 0, 9);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    len = make_ipv6_fragment(test_buffer, FALSE, 0, 9);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert_cmpuint(pkt.anomalies & INET_ANOMALY_FRAG_OVERLAP, ==, 0);
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 1);
    inet_flow_table_free(table);
}

void test_flow_fragment_mismatch()
{
    InetFlowTable *table = inet_flow_table_new();
    guint8 *p;
    guint len;

    setup_test();
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    ip_hdr_t *ip = (ip_hdr_t *) p;
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    len = (guint) (p - test_buffer);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));

    /* A fragment with the same ID but another protocol is another datagram */
    ip->frag_off = GUINT16_TO_BE(1);
    ip->protocol = IP_PROTOCOL_TCP;
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 2);

    /* A fragment with the same ID but another destination is another datagram */
    ip->protocol = IP_PROTOCOL_UDP;
    ip->daddr ^= 1;
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 3);
    inet_flow_table_free(table);
}

void test_flow_parse_malformed_gre()
{
    guint16 protocols[] = { ETH_PROTOCOL_IP, ETH_PROTOCOL_IPV6 };
    guint8 *p;
    guint len;
    int i;

    for (i = 0; i < G_N_ELEMENTS(protocols); i++) {
        setup_test();
        p = build_hdr_eth(test_buffer, protocols[i]);
        p = build_hdr_ip(p, protocols[i], IP_PROTOCOL_GRE, FALSE);
        guint gre_offset = (guint) (p - test_buffer);

        /* The frame ends inside the GRE header */
        len = make_pkt_gre(test_buffer, protocols[i], protocols[i], IP_PROTOCOL_UDP);
        g_assert_false(parse_tuple(test_tuple, test_buffer, gre_offset + 2, TRUE));

        /* The frame ends inside the inner packet */
        g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, TRUE));
    }

    /* The frame ends inside the optional GRE fields */
    setup_test();
    len = make_pkt_gre_flags(test_buffer, GRE_HEADER_CSUM | GRE_HEADER_KEY | GRE_HEADER_SEQ, ETH_PROTOCOL_IP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, sizeof(ethernet_hdr_t) + sizeof(ip_hdr_t) + sizeof(gre_hdr_t) + 8, TRUE));
}

void test_flow_parse_malformed_ipv4_tcp()
{
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len - 4, FALSE));
}

void test_flow_parse_malformed_auth_length()
{
    guint8 *p;

    setup_test();
    /* The authentication header is 24 bytes, but the packet holds 20 of them */
    p = build_hdr_ipv6(test_buffer, IP_PROTOCOL_AUTH, FALSE);
    build_hdr_auth(p, IP_PROTOCOL_UDP);
    g_assert_false(parse_ipv6_tuple(test_tuple, test_buffer, sizeof(ip6_hdr_t) + 20, FALSE));
}

void test_flow_parse_malformed_mpls()
{
    guint len;

    setup_test();
    /* More than three labels */
    len = make_pkt_mpls(test_buffer, 0x1, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, 4);
    g_assert_false(parse_tuple(test_tuple, test_buffer, len, FALSE));

    /* The frame ends inside a label */
    g_assert_false(parse_tuple(test_tuple, test_buffer, sizeof(ethernet_hdr_t) + 2, FALSE));
}

void test_flow_parse_malformed_pppoe()
{
    setup_test();
    make_pkt_pppoe(test_buffer, IP_PROTOCOL_UDP, PPP_PROTOCOL_IPV4);
    /* The frame ends inside the PPPoE header */
    g_assert_false(parse_tuple(test_tuple, test_buffer, sizeof(ethernet_hdr_t) + 4, FALSE));
}

static void count_flows(InetFlow * flow, gpointer data)
{
    (*(int *)data)++;
}

void test_flow_foreach_null()
{
    int count = 0;

    inet_flow_foreach(NULL, (IFFunc) count_flows, &count);
    g_assert_cmpint(count, ==, 0);
}

void test_tuple_set_sockaddr(gconstpointer data)
{
    guint8 family = GPOINTER_TO_UINT(data);
    guint8 src[16] = { 10, 0, 0, 1 }, dst[16] = {
    10, 0, 0, 2};
    struct sockaddr_storage ss;
    InetTuple tuple;

    if (family == AF_INET6) {
        memcpy(src, test_ip6src, sizeof(src));
        memcpy(dst, test_ip6dst, sizeof(dst));
    }
    inet_tuple_set(&tuple, family, IP_PROTOCOL_TCP, src, htons(1234), dst, htons(80));
    g_assert_cmpuint(inet_tuple_family(&tuple), ==, family);
    g_assert_cmpuint(inet_tuple_get_protocol(&tuple), ==, IP_PROTOCOL_TCP);
    g_assert_cmpuint(inet_tuple_get_src_port(&tuple), ==, htons(1234));
    g_assert_cmpuint(inet_tuple_get_dst_port(&tuple), ==, htons(80));

    inet_tuple_to_sockaddr(&tuple, TRUE, &ss);
    g_assert_cmpuint(ss.ss_family, ==, family);
    if (family == AF_INET) {
        g_assert(memcmp(&((struct sockaddr_in *)&ss)->sin_addr, src, 4) == 0);
        g_assert_cmpuint(((struct sockaddr_in *)&ss)->sin_port, ==, htons(1234));
    } else {
        g_assert(memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, src, 16) == 0);
        g_assert_cmpuint(((struct sockaddr_in6 *)&ss)->sin6_port, ==, htons(1234));
    }
    inet_tuple_to_sockaddr(&tuple, FALSE, &ss);
    if (family == AF_INET) {
        g_assert(memcmp(&((struct sockaddr_in *)&ss)->sin_addr, dst, 4) == 0);
        g_assert_cmpuint(((struct sockaddr_in *)&ss)->sin_port, ==, htons(80));
    } else {
        g_assert(memcmp(&((struct sockaddr_in6 *)&ss)->sin6_addr, dst, 16) == 0);
        g_assert_cmpuint(((struct sockaddr_in6 *)&ss)->sin6_port, ==, htons(80));
    }
}

void test_tuple_server_client()
{
    guint8 a[4] = { 10, 0, 0, 1 }, b[4] = {
    10, 0, 0, 2};
    InetTuple tuple;

    /* The server is the end with the lower port */
    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_TCP, a, htons(1234), b, htons(80));
    g_assert_false(tuple_src_is_server(&tuple));
    g_assert(inet_tuple_server_addr(&tuple) == &tuple.dst);
    g_assert_cmpuint(inet_tuple_server_port(&tuple), ==, htons(80));
    g_assert(inet_tuple_client_addr(&tuple) == &tuple.src);
    g_assert_cmpuint(inet_tuple_client_port(&tuple), ==, htons(1234));

    /* With equal ports the server is the end with the lower address */
    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_UDP, a, htons(500), b, htons(500));
    g_assert_true(tuple_src_is_server(&tuple));
    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_UDP, b, htons(500), a, htons(500));
    g_assert_false(tuple_src_is_server(&tuple));
}

void test_tuple_exact_ports()
{
    guint8 a[4] = { 10, 0, 0, 1 }, b[4] = {
    10, 0, 0, 2};
    InetTuple t1, t2;

    inet_tuple_set(&t1, AF_INET, IP_PROTOCOL_TCP, a, htons(1234), b, htons(80));
    inet_tuple_set(&t2, AF_INET, IP_PROTOCOL_TCP, a, htons(1235), b, htons(80));
    g_assert_false(inet_tuple_exact(&t1, &t2));
    g_assert_false(inet_tuple_equal(&t1, &t2));
    inet_tuple_set(&t2, AF_INET, IP_PROTOCOL_TCP, a, htons(1234), b, htons(81));
    g_assert_false(inet_tuple_exact(&t1, &t2));
}

static InetFlow *direction_send(InetFlowTable * table, guint len, guint8 direction)
{
    InetPacket pkt;
    InetFlow *flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt);

    g_assert_nonnull(flow);
    g_assert_cmpuint(pkt.direction, ==, direction);
    return flow;
}

void test_flow_direction(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    guint protocols[] = { IP_PROTOCOL_UDP, eth_protocol == ETH_PROTOCOL_IP ? IP_PROTOCOL_ICMP : IP_PROTOCOL_ICMPV6 };
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;
    guint len;
    int i;

    setup_test();
    /* A TCP flow first seen mid-stream takes its original direction from the first packet */
    len = make_tcp_pkt(test_buffer, eth_protocol, TRUE, ACK, 5000, 1000, 1000, "reply");
    flow = direction_send(table, len, FLOW_DIRECTION_ORIGINAL);
    g_assert_cmpuint(flow->outbytes, ==, len);
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, ACK, 1000, 5005, 1000, "request");
    direction_send(table, len, FLOW_DIRECTION_REPLY);
    g_assert_cmpuint(flow->inbytes, ==, len);

    /* A SYN makes the client direction the original one */
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, SYN, 2000, 0, 1000, NULL);
    direction_send(table, len, FLOW_DIRECTION_ORIGINAL);
    len = make_tcp_pkt(test_buffer, eth_protocol, TRUE, SYN_ACK, 6000, 2001, 1000, NULL);
    direction_send(table, len, FLOW_DIRECTION_REPLY);
    inet_flow_table_free(table);

    /* UDP and ICMP flows take their original direction from the first packet */
    for (i = 0; i < G_N_ELEMENTS(protocols); i++) {
        table = inet_flow_table_new();
        len = make_pkt_reverse(test_buffer, eth_protocol, protocols[i]);
        flow = direction_send(table, len, FLOW_DIRECTION_ORIGINAL);
        len = make_pkt(test_buffer, eth_protocol, protocols[i]);
        direction_send(table, len, FLOW_DIRECTION_REPLY);
        g_assert_cmpuint(flow->outbytes, ==, len);
        g_assert_cmpuint(flow->inbytes, ==, len);
        if (protocols[i] == IP_PROTOCOL_UDP)
            g_assert_cmpuint(flow->state, ==, FLOW_OPEN);
        inet_flow_table_free(table);
    }

    /* With the same port at each end the addresses give the direction */
    TEST_DPORT = TEST_SPORT;
    table = inet_flow_table_new();
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, SYN, 2000, 0, 1000, NULL);
    direction_send(table, len, FLOW_DIRECTION_ORIGINAL);
    len = make_tcp_pkt(test_buffer, eth_protocol, TRUE, SYN_ACK, 6000, 2001, 1000, NULL);
    direction_send(table, len, FLOW_DIRECTION_REPLY);
    len = make_pkt(test_buffer, eth_protocol, IP_PROTOCOL_UDP);
    flow = direction_send(table, len, FLOW_DIRECTION_ORIGINAL);
    len = make_pkt_reverse(test_buffer, eth_protocol, IP_PROTOCOL_UDP);
    direction_send(table, len, FLOW_DIRECTION_REPLY);
    g_assert_cmpuint(flow->state, ==, FLOW_OPEN);
    inet_flow_table_free(table);
    TEST_DPORT = _TEST_DPORT;
}

void test_packet_tcp(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, SYN, 1000, 0, 512, NULL);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt)));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));
    g_assert(pkt.l4 == test_buffer + len - sizeof(tcp_hdr_t));
    g_assert_cmpuint(pkt.direction, ==, FLOW_DIRECTION_ORIGINAL);
    g_assert_cmpuint(pkt.tcp.flags, ==, SYN);
    g_assert_cmpuint(pkt.tcp.seq, ==, 1000);
    g_assert_cmpuint(pkt.tcp.ack, ==, 0);
    g_assert_cmpuint(pkt.tcp.window, ==, 512);
    g_assert(pkt.payload == test_buffer + len);
    g_assert_cmpuint(pkt.payload_length, ==, 0);
    g_assert_false(pkt.fragment);

    len = make_tcp_pkt(test_buffer, eth_protocol, TRUE, ACK | 0x0008, 5000, 1001, 1024, "hello");
    g_assert(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt) == flow);
    g_assert_cmpuint(pkt.direction, ==, FLOW_DIRECTION_REPLY);
    g_assert_cmpuint(pkt.tcp.flags, ==, ACK | 0x0008);
    g_assert_cmpuint(pkt.tcp.seq, ==, 5000);
    g_assert_cmpuint(pkt.tcp.ack, ==, 1001);
    g_assert_cmpuint(pkt.tcp.window, ==, 1024);
    g_assert_cmpuint(pkt.payload_length, ==, 5);
    g_assert(memcmp(pkt.payload, "hello", 5) == 0);
    inet_flow_table_free(table);
}

void test_packet_padding(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetPacket pkt;
    guint len;

    setup_test();
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, ACK, 1, 1, 1, "ab");
    /* Link layer padding after the IP packet is not payload */
    g_assert_true(inet_packet_parse(test_buffer, len + 10, INET_FLOW_L2, NULL, &pkt));
    g_assert_cmpuint(pkt.payload_length, ==, 2);
}

void test_packet_jumbogram()
{
    InetPacket pkt;
    guint len;

    setup_test();
    /* A payload length of zero does not limit the packet */
    len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IPV6, FALSE, ACK, 1, 1, 1, "ab");
    ((ip6_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->pay_len = 0;
    g_assert_true(inet_packet_parse(test_buffer, len, INET_FLOW_L2, NULL, &pkt));
    g_assert_cmpuint(pkt.payload_length, ==, 2);
}

void test_packet_udp()
{
    InetPacket pkt;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    memcpy(test_buffer + len, "data", 4);
    g_assert_true(inet_packet_parse(test_buffer, len + 4, INET_FLOW_L2, NULL, &pkt));
    g_assert(pkt.l4 == test_buffer + len - sizeof(udp_hdr_t));
    g_assert(pkt.payload == test_buffer + len);
    g_assert_cmpuint(pkt.payload_length, ==, 4);
    g_assert_cmpuint(pkt.tcp.flags, ==, 0);
}

void test_packet_ipv6_ext()
{
    InetPacket pkt;
    guint8 *p, *tcp;

    setup_test();
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ipv6(p, IP_PROTOCOL_DEST_OPT, FALSE);
    p = build_hdr_ipv6_part(p, IP_PROTOCOL_TCP);
    tcp = p;
    p = build_tcp_segment(p, FALSE, SYN, 1, 0, 1, "x");
    g_assert_true(inet_packet_parse(test_buffer, (guint) (p - test_buffer), INET_FLOW_L2, NULL, &pkt));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));
    g_assert(pkt.l4 == tcp);
    g_assert_cmpuint(pkt.payload_length, ==, 1);
}

void test_packet_fragment(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint8 *p;
    guint len;

    setup_test();
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    len = (guint) (p - test_buffer);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert_nonnull(pkt.l4);
    g_assert_true(pkt.fragment);

    /* The transport header is not in a non-first fragment */
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, FALSE, 1, 0xbeef);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert(pkt.l3 == test_buffer + sizeof(ethernet_hdr_t));
    g_assert_null(pkt.l4);
    g_assert_null(pkt.payload);
    g_assert_true(pkt.fragment);
    inet_flow_table_free(table);
}

void test_flow_get_not_found()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);

    /* Without INET_FLOW_CREATE no flow is created */
    g_assert_null(inet_flow_get(table, test_buffer, len, 0, INET_FLOW_L2, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_NOT_FOUND);
    g_assert_cmpuint(inet_flow_table_size(table), ==, 0);

    /* Without INET_FLOW_UPDATE the flow is found but not counted */
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt)));
    g_assert(inet_flow_get(table, test_buffer, len, 0, INET_FLOW_L2, &pkt) == flow);
    g_assert_cmpint(pkt.status, ==, INET_PACKET_OK);
    g_assert_cmpuint(pkt.direction, ==, FLOW_DIRECTION_UNKNOWN);
    g_assert_cmpuint(flow->packets, ==, 1);
    inet_flow_table_free(table);
}

void test_flow_get_table_full()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint len;

    setup_test();
    inet_flow_table_max_set(table, 1);
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_null(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_TABLE_FULL);
    inet_flow_table_free(table);
}

/* Look up a frame in a new table and return the anomalies reported for it */
static guint32 frame_anomalies(guint len, gboolean expect_flow)
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt);

    g_assert(expect_flow == (flow != NULL));
    inet_flow_table_free(table);
    return pkt.anomalies;
}

static guint make_udp_pkt(guint8 * buffer, guint16 eth_protocol, guint payload_len)
{
    guint8 *ip = build_hdr_eth(buffer, eth_protocol);
    guint8 *udp = build_hdr_ip(ip, eth_protocol, IP_PROTOCOL_UDP, FALSE);
    guint8 *p = build_hdr_udp(udp, FALSE) + payload_len;

    ((udp_hdr_t *) udp)->length = g_htons(p - udp);
    if (eth_protocol == ETH_PROTOCOL_IP)
        ((ip_hdr_t *) ip)->tot_len = g_htons(p - ip);
    else
        ((ip6_hdr_t *) ip)->pay_len = g_htons(p - ip - sizeof(ip6_hdr_t));
    return (guint) (p - buffer);
}

void test_anomaly_none()
{
    setup_test();
    guint len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IP, FALSE, SYN, 1, 0, 1, "x");
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, 0);
    len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IPV6, FALSE, SYN, 1, 0, 1, "x");
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, 0);
    len = make_udp_pkt(test_buffer, ETH_PROTOCOL_IP, 4);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, 0);
    len = make_udp_pkt(test_buffer, ETH_PROTOCOL_IPV6, 4);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, 0);
}

void test_anomaly_ip_version()
{
    setup_test();
    guint len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IP, FALSE, SYN, 1, 0, 1, NULL);
    ((ip_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->ihl_version = 0x55;
    g_assert_cmphex(frame_anomalies(len, FALSE), ==, INET_ANOMALY_IP_VERSION);
}

void test_anomaly_ipv4()
{
    setup_test();
    ip_hdr_t *ip = (ip_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t));
    guint len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IP, FALSE, SYN, 1, 0, 1, "abcd");

    /* Frame ends inside the fixed header */
    g_assert_cmphex(frame_anomalies(sizeof(ethernet_hdr_t) + 10, FALSE), ==, INET_ANOMALY_IPV4_TRUNCATED);

    /* Frame ends before the total length */
    g_assert_cmphex(frame_anomalies(len - 2, TRUE), ==, INET_ANOMALY_IPV4_TRUNCATED);

    /* Total length shorter than the header */
    ip->tot_len = g_htons(10);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, INET_ANOMALY_IPV4_LEN_TOO_SMALL);
    ip->tot_len = g_htons(len - sizeof(ethernet_hdr_t));

    /* Header length below the minimum */
    ip->ihl_version = 0x44;
    g_assert_cmphex(frame_anomalies(len, FALSE), ==, INET_ANOMALY_IPV4_HLEN_TOO_SMALL);

    /* Header length past the end of the frame */
    ip->ihl_version = 0x4f;
    g_assert_cmphex(frame_anomalies(sizeof(ethernet_hdr_t) + 40, FALSE), ==, INET_ANOMALY_IPV4_TRUNCATED);
}

void test_anomaly_ipv6()
{
    guint8 *p;

    setup_test();
    guint len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IPV6, FALSE, SYN, 1, 0, 1, "abcd");

    /* Frame ends inside the fixed header */
    g_assert_cmphex(frame_anomalies(sizeof(ethernet_hdr_t) + 20, FALSE), ==, INET_ANOMALY_IPV6_TRUNCATED);

    /* Frame ends before the payload length */
    g_assert_cmphex(frame_anomalies(len - 2, TRUE), ==, INET_ANOMALY_IPV6_TRUNCATED);

    /* Extension header past the end of the frame */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IPV6);
    p = build_hdr_ipv6(p, IP_PROTOCOL_DEST_OPT, FALSE);
    ((ip6_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->pay_len = 0;
    p = build_hdr_ipv6_part(p, IP_PROTOCOL_TCP);
    len = (guint) (p - test_buffer);
    g_assert_cmphex(frame_anomalies(len - 8, FALSE), ==, INET_ANOMALY_IPV6_EXTHDR_TRUNCATED);
}

void test_anomaly_tcp(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    guint ip_hdr_len = eth_protocol == ETH_PROTOCOL_IP ? sizeof(ip_hdr_t) : sizeof(ip6_hdr_t);
    tcp_hdr_t *tcp = (tcp_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t) + ip_hdr_len);
    guint len;

    setup_test();

    /* Data offset below the minimum */
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, SYN, 1, 0, 1, "abcd");
    tcp->flags = g_htons(0x4000 | SYN);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, INET_ANOMALY_TCP_HLEN_TOO_SMALL);

    /* Data offset past the end of the packet */
    tcp->flags = g_htons(0xf000 | SYN);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, INET_ANOMALY_TCP_TRUNCATED);

    /* Fixed header past the end of the packet */
    len = make_tcp_pkt(test_buffer, eth_protocol, FALSE, SYN, 1, 0, 1, NULL);
    if (eth_protocol == ETH_PROTOCOL_IP)
        ((ip_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->tot_len = 0;
    else
        ((ip6_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->pay_len = 0;
    g_assert_cmphex(frame_anomalies(len - 4, FALSE) & ~INET_ANOMALY_IPV4_LEN_TOO_SMALL, ==, INET_ANOMALY_TCP_TRUNCATED);
}

void test_anomaly_udp(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    guint ip_hdr_len = eth_protocol == ETH_PROTOCOL_IP ? sizeof(ip_hdr_t) : sizeof(ip6_hdr_t);
    udp_hdr_t *udp = (udp_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t) + ip_hdr_len);
    guint len;

    setup_test();
    len = make_udp_pkt(test_buffer, eth_protocol, 4);

    /* Length field below the header size */
    udp->length = g_htons(4);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, INET_ANOMALY_UDP_LEN_INVALID);

    /* Length field past the end of the packet */
    udp->length = g_htons(100);
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, INET_ANOMALY_UDP_LEN_INVALID);

    /* Header past the end of the packet */
    if (eth_protocol == ETH_PROTOCOL_IP)
        ((ip_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->tot_len = 0;
    else
        ((ip6_hdr_t *) (test_buffer + sizeof(ethernet_hdr_t)))->pay_len = 0;
    g_assert_cmphex(frame_anomalies(len - 8, FALSE) & ~INET_ANOMALY_IPV4_LEN_TOO_SMALL, ==, INET_ANOMALY_UDP_TRUNCATED);
}

void test_anomaly_udp_fragment()
{
    guint8 *p;
    guint len;

    setup_test();
    /* The UDP length of a first fragment covers data in later fragments */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    ip_hdr_t *ip = (ip_hdr_t *) p;
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 0xbeef);
    ((udp_hdr_t *) (p - sizeof(udp_hdr_t)))->length = g_htons(1000);
    len = (guint) (p - test_buffer);
    ip->tot_len = g_htons(len - sizeof(ethernet_hdr_t));
    g_assert_cmphex(frame_anomalies(len, TRUE), ==, 0);
}

/* Build an IPv4 TCP SYN with the given option bytes and return the anomalies
 * and the packet information for it */
static guint32 tcp_options_info(const guint8 * opts, guint opts_len, InetPacket * pkt)
{
    InetFlowTable *table = inet_flow_table_new();
    guint8 *ip = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    guint8 *tcp = build_hdr_ip(ip, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP, FALSE);
    guint8 *p = build_tcp_segment(tcp, FALSE, SYN, 1, 0, 1, NULL);

    memcpy(p, opts, opts_len);
    p += opts_len;
    ((tcp_hdr_t *) tcp)->flags = g_htons((((p - tcp) / 4) << 12) | SYN);
    ((ip_hdr_t *) ip)->tot_len = g_htons(p - ip);
    g_assert_nonnull(inet_flow_get(table, test_buffer, (guint) (p - test_buffer), 0, FLOW_GET | INET_FLOW_VALIDATE, pkt));
    inet_flow_table_free(table);
    return pkt->anomalies;
}

void test_tcp_options()
{
    InetPacket pkt;
    const guint8 opts[] = {
        TCP_OPT_MSS, 4, 0x05, 0xb4,
        OPT_NOP, TCP_OPT_WSCALE, 3, 7,
        OPT_NOP, OPT_NOP, TCP_OPT_TIMESTAMP, 10, 0, 0, 0x12, 0x34, 0, 0, 0x56, 0x78,
        OPT_NOP, OPT_NOP, TCP_OPT_SACK_PERMITTED, 2,
        OPT_NOP, OPT_NOP, TCP_OPT_SACK, 10, 0, 0, 0, 1, 0, 0, 0, 2,
    };

    setup_test();
    g_assert_cmphex(tcp_options_info(opts, sizeof(opts), &pkt), ==, 0);
    g_assert_cmphex(pkt.tcp.options, ==, INET_TCP_OPT_MSS | INET_TCP_OPT_WSCALE |
                    INET_TCP_OPT_TIMESTAMP | INET_TCP_OPT_SACK_PERMITTED | INET_TCP_OPT_SACK);
    g_assert_cmpuint(pkt.tcp.mss, ==, 1460);
    g_assert_cmpuint(pkt.tcp.wscale, ==, 7);
    g_assert_cmpuint(pkt.tcp.ts_val, ==, 0x1234);
    g_assert_cmpuint(pkt.tcp.ts_ecr, ==, 0x5678);
    g_assert_cmpuint(pkt.payload_length, ==, 0);
}

void test_tcp_options_invalid()
{
    InetPacket pkt;
    const guint8 short_mss[] = { TCP_OPT_MSS, 3, 0x05, 0 };
    const guint8 zero_len[] = { OPT_NOP, OPT_NOP, 0x22, 0 };
    const guint8 past_end[] = { OPT_NOP, OPT_NOP, 0x22, 8 };
    const guint8 bad_sack[] = { OPT_NOP, OPT_NOP, TCP_OPT_SACK, 6, 0, 0, 0, 0 };
    const guint8 dup_wscale[] = { TCP_OPT_WSCALE, 3, 1, TCP_OPT_WSCALE, 3, 2, OPT_NOP, OPT_NOP };
    const guint8 end_list[] = { OPT_END, 0x22, 0, 0 };

    setup_test();
    g_assert_cmphex(tcp_options_info(short_mss, sizeof(short_mss), &pkt), ==, INET_ANOMALY_TCP_OPT_INVALID);
    g_assert_cmphex(pkt.tcp.options, ==, 0);
    g_assert_cmphex(tcp_options_info(zero_len, sizeof(zero_len), &pkt), ==, INET_ANOMALY_TCP_OPT_INVALID);
    g_assert_cmphex(tcp_options_info(past_end, sizeof(past_end), &pkt), ==, INET_ANOMALY_TCP_OPT_INVALID);
    g_assert_cmphex(tcp_options_info(bad_sack, sizeof(bad_sack), &pkt), ==, INET_ANOMALY_TCP_OPT_INVALID);
    g_assert_cmphex(tcp_options_info(dup_wscale, sizeof(dup_wscale), &pkt), ==, INET_ANOMALY_TCP_OPT_DUPLICATE);
    g_assert_cmpuint(pkt.tcp.wscale, ==, 1);
    /* Bytes after the end of option list option are padding */
    g_assert_cmphex(tcp_options_info(end_list, sizeof(end_list), &pkt), ==, 0);
}

void test_ipv4_options_invalid()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint8 *p;
    guint len;

    setup_test();
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    guint8 *opts = p + sizeof(ip_hdr_t);
    p = build_hdr_ipv4_options(p, IP_PROTOCOL_TCP, 8);
    p = build_hdr_tcp(p, FALSE);
    len = (guint) (p - test_buffer);

    /* Valid option */
    opts[0] = 0x94;
    opts[1] = 4;
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET | INET_FLOW_VALIDATE, &pkt));
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_IPV4_OPT_INVALID, ==, 0);

    /* Option that extends past the header */
    opts[4] = 0x94;
    opts[5] = 6;
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET | INET_FLOW_VALIDATE, &pkt));
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_IPV4_OPT_INVALID, ==, INET_ANOMALY_IPV4_OPT_INVALID);
    inet_flow_table_free(table);
}

void test_options_not_validated()
{
    const guint8 opts[] = { TCP_OPT_MSS, 3, 0x05, 0 };
    InetFlowTable *table;
    InetPacket pkt;
    guint len;

    /* Without INET_FLOW_VALIDATE the options are not checked */
    setup_test();
    tcp_options_info(opts, sizeof(opts), &pkt);
    len = (guint) (pkt.payload - test_buffer);
    table = inet_flow_table_new();
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, &pkt));
    g_assert_cmphex(pkt.anomalies, ==, 0);
    g_assert_cmphex(pkt.tcp.options, ==, 0);
    inet_flow_table_free(table);
}

/* Send one fragment of datagram 0xbeef holding extra bytes after the UDP
 * header, and return the flow. The packet details are returned in pkt. */
static InetFlow *send_fragment(InetFlowTable * table, guint16 eth_protocol, guint16 offset,
                               gboolean more, guint extra, guint64 ts, guint16 id, InetPacket * pkt)
{
    guint8 *p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, more, offset, id);
    return inet_flow_get(table, test_buffer, (guint) (p - test_buffer) + extra, ts, FLOW_GET, pkt);
}

/* Datagrams in flight between the same two hosts are told apart by their IDs */
void test_fragment_many_datagrams(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    const guint16 count = 500;
    InetPacket pkt;
    guint16 id;

    setup_test();
    inet_flow_table_frag_limits_set(table, count, 30);
    for (id = 0; id < count; id++) {
        TEST_SPORT = 10000 + id;
        g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, 1000, id, &pkt));
    }
    TEST_SPORT = _TEST_SPORT;
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, count);

    /* The last fragments arrive in the reverse order and complete each datagram */
    for (id = count; id-- > 0;) {
        g_assert_nonnull(send_fragment(table, eth_protocol, 1, FALSE, 0, 1000, id, &pkt));
        g_assert_cmpuint(pkt.tuple.sport, ==, htons(10000 + id));
    }
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 0);
    g_assert_null(table->frag_info_list->age.head);
    inet_flow_table_free(table);
}

/* A full list clears the expired datagrams, oldest first, and keeps the rest */
void test_fragment_expiry_order(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    guint64 ts = 1000;
    InetFragment *oldest;
    InetPacket pkt;

    setup_test();
    inet_flow_table_frag_limits_set(table, 3, 30);
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, ts, 1, &pkt));
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, ts + 10 * TIMESTAMP_RESOLUTION_US, 2, &pkt));
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, ts + 20 * TIMESTAMP_RESOLUTION_US, 3, &pkt));

    /* Only the first datagram has expired, so the new one takes its place */
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, ts + 35 * TIMESTAMP_RESOLUTION_US, 4, &pkt));
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 3);
    oldest = table->frag_info_list->age.head->data;
    g_assert_cmpuint(oldest->timestamp, ==, ts + 10 * TIMESTAMP_RESOLUTION_US);

    /* Nothing has expired, so another datagram can not be tracked */
    g_assert_null(send_fragment(table, eth_protocol, 0, TRUE, 0, ts + 36 * TIMESTAMP_RESOLUTION_US, 5, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_FRAG_UNTRACKED);
    inet_flow_table_free(table);
}

void test_fragment_overlap(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;

    setup_test();
    /* First fragment holds bytes 0 to 23 */
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 16, 0, 0xbeef, &pkt));
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_OVERLAP, ==, 0);

    /* Second fragment starts at byte 16 */
    g_assert_nonnull(send_fragment(table, eth_protocol, 2, TRUE, 0, 0, 0xbeef, &pkt));
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_OVERLAP, ==, INET_ANOMALY_FRAG_OVERLAP);

    /* Third fragment follows on from the second without overlap */
    g_assert_nonnull(send_fragment(table, eth_protocol, 3, FALSE, 0, 0, 0xbeef, &pkt));
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_OVERLAP, ==, 0);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);
    inet_flow_table_free(table);
}

void test_fragment_too_large(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;

    setup_test();
    g_assert_nonnull(send_fragment(table, eth_protocol, 0, TRUE, 0, 0, 0xbeef, &pkt));
    /* The last fragment ends past 65535 bytes */
    send_fragment(table, eth_protocol, 0x1fff, FALSE, 0, 0, 0xbeef, &pkt);
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_TOO_LARGE, ==, INET_ANOMALY_FRAG_TOO_LARGE);
    send_fragment(table, eth_protocol, 0x1000, FALSE, 0, 0, 0xbeef, &pkt);
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_TOO_LARGE, ==, 0);
    inet_flow_table_free(table);
}

void test_fragment_out_of_order(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *first, *last;
    InetPacket pkt;

    setup_test();
    /* The middle fragment arrives before the first fragment */
    g_assert_nonnull(send_fragment(table, eth_protocol, 1, TRUE, 0, 0, 0xbeef, &pkt));
    g_assert_nonnull((first = send_fragment(table, eth_protocol, 0, TRUE, 0, 0, 0xbeef, &pkt)));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);

    /* The last fragment gets the ports from the first fragment */
    g_assert_nonnull((last = send_fragment(table, eth_protocol, 2, FALSE, 0, 0, 0xbeef, &pkt)));
    g_assert(first == last);
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_OVERLAP, ==, 0);
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);
    inet_flow_table_free(table);
}

void test_fragment_last_first()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;

    setup_test();
    /* The last fragment arriving first does not end the tracking */
    g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, 1, FALSE, 0, 0, 0xbeef, &pkt));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 1);
    g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, 0, TRUE, 0, 0, 0xbeef, &pkt));
    g_assert(g_hash_table_size(table->frag_info_list->table) == 0);
    inet_flow_table_free(table);
}


void test_fragment_expired()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    guint64 now = get_time_us();

    setup_test();
    g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, 0, TRUE, 0, now, 0xbeef, &pkt));
    send_fragment(table, ETH_PROTOCOL_IP, 1, TRUE, 0, now + (FRAG_EXPIRY_TIME + 1) * TIMESTAMP_RESOLUTION_US, 0xbeef, &pkt);
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_EXPIRED, ==, INET_ANOMALY_FRAG_EXPIRED);
    inet_flow_table_free(table);
}

void test_fragment_many_ranges()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFragment *entry;
    InetPacket pkt;
    int i;

    setup_test();
    /* Fragments with gaps between them, more than the ranges recorded */
    for (i = 0; i <= INET_FRAG_MAX_RANGES; i++)
        g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, i * 2, TRUE, 0, 0, 0xbeef, &pkt));
    g_assert_cmpuint(g_hash_table_size(table->frag_info_list->table), ==, 1);
    entry = table->frag_info_list->age.head->data;
    g_assert_cmpuint(entry->nranges, ==, INET_FRAG_MAX_RANGES);
    inet_flow_table_free(table);
}

void test_fragment_no_list(gconstpointer data)
{
    guint16 eth_protocol = GPOINTER_TO_UINT(data);
    InetPacket pkt;
    guint8 *p;

    setup_test();
    /* Without a fragment list a non-first fragment has no ports */
    p = build_hdr_eth(test_buffer, eth_protocol);
    p = build_hdr_ip_fragment(p, eth_protocol, IP_PROTOCOL_UDP, FALSE, FALSE, 0x1fff, 0xbeef);
    g_assert_true(inet_packet_parse(test_buffer, (guint) (p - test_buffer), INET_FLOW_L2, NULL, &pkt));
    g_assert_true(pkt.fragment);
    g_assert_cmpuint(pkt.tuple.sport, ==, 0);
    g_assert_cmphex(pkt.anomalies & INET_ANOMALY_FRAG_TOO_LARGE, ==, INET_ANOMALY_FRAG_TOO_LARGE);
}

/* TCP tracking tests. The client is TEST_SADDR:TEST_SPORT. */
static guint16 tcp_eth_protocol = ETH_PROTOCOL_IP;
static const guint8 *tcp_opts;
static guint tcp_opts_len;

/* Send one segment and track it. Returns FALSE if the segment is invalid. */
static gboolean tcp_send(InetFlowTable * table, InetFlow ** flow, gboolean from_client,
                         guint16 flags, guint32 seq, guint32 ack, guint16 window, guint payload_len, InetPacket * pkt)
{
    guint8 *ip = build_hdr_eth(test_buffer, tcp_eth_protocol);
    guint8 *tcp = build_hdr_ip(ip, tcp_eth_protocol, IP_PROTOCOL_TCP, !from_client);
    guint8 *p = build_tcp_segment(tcp, !from_client, flags, seq, ack, window, NULL);

    memcpy(p, tcp_opts, tcp_opts_len);
    p += tcp_opts_len;
    ((tcp_hdr_t *) tcp)->flags = g_htons((((p - tcp) / 4) << 12) | flags);
    memset(p, 0x61, payload_len);
    p += payload_len;
    if (tcp_eth_protocol == ETH_PROTOCOL_IP)
        ((ip_hdr_t *) ip)->tot_len = g_htons(p - ip);
    else
        ((ip6_hdr_t *) ip)->pay_len = g_htons(p - ip - sizeof(ip6_hdr_t));

    *flow = inet_flow_get(table, test_buffer, (guint) (p - test_buffer), 0, FLOW_GET | INET_FLOW_TCP_TRACK, pkt);
    g_assert_nonnull(*flow);
    g_assert_cmphex(pkt->anomalies, ==, 0);
    return !pkt->tcp.invalid;
}

/* Send a valid segment that raises no events */
static void tcp_send_ok(InetFlowTable * table, InetFlow ** flow, gboolean from_client,
                        guint16 flags, guint32 seq, guint32 ack, guint16 window, guint payload_len, InetTcpConnState state)
{
    InetPacket pkt;

    g_assert_true(tcp_send(table, flow, from_client, flags, seq, ack, window, payload_len, &pkt));
    g_assert_cmphex(pkt.tcp.events, ==, 0);
    g_assert_cmpint(inet_flow_tcp_state(*flow), ==, state);
}

/* Send a segment and check the events it raises and whether it is invalid */
static void tcp_send_events(InetFlowTable * table, InetFlow ** flow, gboolean from_client,
                            guint16 flags, guint32 seq, guint32 ack, guint16 window, guint payload_len, guint32 events, gboolean invalid)
{
    InetPacket pkt;

    g_assert(tcp_send(table, flow, from_client, flags, seq, ack, window, payload_len, &pkt)
             == !invalid);
    g_assert_cmphex(pkt.tcp.events, ==, events);
    g_assert(pkt.tcp.invalid == invalid);
}

/* Client ISN 100, server ISN 500, both windows 1000 */
static InetFlow *tcp_establish(InetFlowTable * table)
{
    InetFlow *flow;

    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    return flow;
}

static void tcp_test_setup(gconstpointer data)
{
    setup_test();
    tcp_eth_protocol = GPOINTER_TO_UINT(data);
    tcp_opts = NULL;
    tcp_opts_len = 0;
}

void test_tcp_track_client_close(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;

    tcp_test_setup(data);
    g_assert_true(tcp_send(table, &flow, TRUE, SYN, 100, 0, 1000, 0, &pkt));
    g_assert_cmpint(pkt.tcp.state, ==, INET_TCP_STATE_NONE);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 10, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 111, 1000, 5, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, TRUE, FIN_ACK, 111, 506, 1000, 0, INET_TCP_STATE_FIN_WAIT1);
    tcp_send_ok(table, &flow, FALSE, ACK, 506, 112, 1000, 0, INET_TCP_STATE_FIN_WAIT2);
    g_assert_true(tcp_send(table, &flow, FALSE, FIN_ACK, 506, 112, 1000, 0, &pkt));
    g_assert_cmpint(pkt.tcp.state, ==, INET_TCP_STATE_FIN_WAIT2);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_TIME_WAIT);
    tcp_send_ok(table, &flow, TRUE, ACK, 112, 507, 1000, 0, INET_TCP_STATE_TIME_WAIT);
    inet_flow_table_free(table);
}

void test_tcp_track_server_close(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    flow = tcp_establish(table);
    tcp_send_ok(table, &flow, FALSE, FIN_ACK, 501, 101, 1000, 0, INET_TCP_STATE_CLOSE_WAIT);
    tcp_send_ok(table, &flow, TRUE, FIN_ACK, 101, 502, 1000, 0, INET_TCP_STATE_LAST_ACK);
    tcp_send_ok(table, &flow, FALSE, ACK, 502, 102, 1000, 0, INET_TCP_STATE_CLOSED);
    inet_flow_table_free(table);
}

void test_tcp_track_simultaneous_close(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    flow = tcp_establish(table);
    tcp_send_ok(table, &flow, TRUE, FIN_ACK, 101, 501, 1000, 0, INET_TCP_STATE_FIN_WAIT1);
    /* The server FIN does not acknowledge the client FIN */
    tcp_send_ok(table, &flow, FALSE, FIN_ACK, 501, 101, 1000, 0, INET_TCP_STATE_CLOSING);
    tcp_send_ok(table, &flow, FALSE, ACK, 502, 102, 1000, 0, INET_TCP_STATE_TIME_WAIT);
    inet_flow_table_free(table);
}

/* A new connection on the tuple of a closed connection is tracked */
void test_tcp_track_reuse(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow, *first;
    InetPacket pkt;

    tcp_test_setup(data);
    first = flow = tcp_establish(table);
    tcp_send_ok(table, &flow, TRUE, RST, 101, 0, 0, 0, INET_TCP_STATE_CLOSED);

    /* A retransmission of the old SYN does not reopen the connection */
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_CLOSED);

    g_assert_true(tcp_send(table, &flow, TRUE, SYN, 9000, 0, 1000, 0, &pkt));
    g_assert_cmpint(pkt.tcp.state, ==, INET_TCP_STATE_CLOSED);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 7000, 9001, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 9001, 7001, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    g_assert(flow == first);

    /* The same after a close that ends in TIME_WAIT */
    tcp_send_ok(table, &flow, TRUE, FIN_ACK, 9001, 7001, 1000, 0, INET_TCP_STATE_FIN_WAIT1);
    tcp_send_ok(table, &flow, FALSE, FIN_ACK, 7001, 9002, 1000, 0, INET_TCP_STATE_TIME_WAIT);
    tcp_send_events(table, &flow, TRUE, SYN, 9000, 0, 1000, 0, INET_TCP_EVENT_SYN_RESEND, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_TIME_WAIT);
    tcp_send_ok(table, &flow, TRUE, SYN, 20000, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 30000, 20001, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 20001, 30001, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    inet_flow_table_free(table);
}

void test_tcp_track_untracked(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    /* A connection first seen with data is not tracked */
    tcp_send_ok(table, &flow, TRUE, ACK, 7000, 9000, 1000, 10, INET_TCP_STATE_UNTRACKED);
    tcp_send_ok(table, &flow, FALSE, ACK, 1, 2, 0, 10, INET_TCP_STATE_UNTRACKED);
    tcp_send_ok(table, &flow, TRUE, SYN, 1, 0, 0, 0, INET_TCP_STATE_UNTRACKED);
    inet_flow_table_free(table);
}

void test_tcp_track_one_sided(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    /* Only the server side of the handshake is seen */
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_EVENT_ONE_SIDED, TRUE);
    tcp_send_events(table, &flow, FALSE, ACK, 501, 101, 1000, 10, INET_TCP_EVENT_ONE_SIDED, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_ONE_SIDED);
    inet_flow_table_free(table);

    /* Only the client side of the handshake is seen */
    table = inet_flow_table_new();
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_events(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_EVENT_ONE_SIDED, TRUE);
    tcp_send_events(table, &flow, TRUE, ACK, 101, 501, 1000, 10, INET_TCP_EVENT_ONE_SIDED, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_ONE_SIDED);
    inet_flow_table_free(table);
}

void test_tcp_track_handshake_errors(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_events(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_EVENT_SYN_RESEND, FALSE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 999, 1000, 0, INET_TCP_EVENT_SYNACK_WRONG_ACK, TRUE);
    tcp_send_events(table, &flow, TRUE, SYN_ACK, 100, 0, 1000, 0, INET_TCP_EVENT_SYNACK_WRONG_DIR, TRUE);
    tcp_send_events(table, &flow, FALSE, ACK, 500, 101, 1000, 0, INET_TCP_EVENT_ACK_WRONG_DIR, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_SYN_SENT);

    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND, FALSE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 102, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND_DIFF_ACK, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 600, 101, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND_DIFF_SEQ, TRUE);
    tcp_send_events(table, &flow, TRUE, SYN, 200, 0, 1000, 0, INET_TCP_EVENT_SYN_RESEND_DIFF_SEQ, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN, 500, 0, 1000, 0, INET_TCP_EVENT_SYN_WRONG_DIR, TRUE);
    tcp_send_events(table, &flow, TRUE, SYN_ACK, 100, 501, 1000, 0, INET_TCP_EVENT_SYNACK_WRONG_DIR, TRUE);
    tcp_send_events(table, &flow, FALSE, ACK, 501, 101, 1000, 0, INET_TCP_EVENT_ACK_WRONG_DIR, TRUE);
    tcp_send_events(table, &flow, TRUE, ACK, 101, 999, 1000, 0, INET_TCP_EVENT_RIGHT_SEQ_WRONG_ACK, TRUE);
    tcp_send_events(table, &flow, TRUE, ACK, 300, 999, 1000, 0, INET_TCP_EVENT_WRONG_SEQ | INET_TCP_EVENT_INVALID_ACK, TRUE);
    tcp_send_events(table, &flow, TRUE, ACK, 300, 501, 1000, 0, INET_TCP_EVENT_WRONG_SEQ, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    inet_flow_table_free(table);
}

void test_tcp_track_handshake_rst(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    /* A RST that does not acknowledge the SYN */
    tcp_send_events(table, &flow, FALSE, RST | ACK, 0, 50, 0, 0, INET_TCP_EVENT_INVALID_RST, TRUE);
    /* A port that is not open */
    tcp_send_ok(table, &flow, FALSE, RST | ACK, 0, 101, 0, 0, INET_TCP_STATE_CLOSED);
    inet_flow_table_free(table);

    table = inet_flow_table_new();
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_events(table, &flow, FALSE, RST, 900, 0, 0, 0, INET_TCP_EVENT_INVALID_RST, TRUE);
    tcp_send_ok(table, &flow, FALSE, RST, 501, 0, 0, 0, INET_TCP_STATE_CLOSED);
    inet_flow_table_free(table);
}

void test_tcp_track_established(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    flow = tcp_establish(table);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 100, INET_TCP_STATE_ESTABLISHED);

    /* Data sent again before it is acknowledged */
    tcp_send_events(table, &flow, TRUE, ACK, 101, 501, 1000, 100, INET_TCP_EVENT_RETRANSMISSION, FALSE);
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 201, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    /* Data sent again after it is acknowledged */
    tcp_send_events(table, &flow, TRUE, ACK, 101, 501, 1000, 100, INET_TCP_EVENT_RETRANSMISSION | INET_TCP_EVENT_BEFORE_LAST_ACK, FALSE);
    /* Keep-alive */
    tcp_send_ok(table, &flow, TRUE, ACK, 200, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, TRUE, ACK, 200, 501, 1000, 1, INET_TCP_STATE_ESTABLISHED);
    /* Data past the server window of 1000 bytes */
    tcp_send_events(table, &flow, TRUE, ACK, 1300, 501, 1000, 10, INET_TCP_EVENT_OUT_OF_WINDOW, TRUE);
    /* ACK for data the server has not sent */
    tcp_send_events(table, &flow, TRUE, ACK, 201, 900, 1000, 0, INET_TCP_EVENT_INVALID_ACK, TRUE);
    /* An invalid packet does not move the sequence numbers on */
    tcp_send_ok(table, &flow, TRUE, ACK, 201, 501, 1000, 10, INET_TCP_STATE_ESTABLISHED);
    /* SYN and SYN/ACK after the handshake */
    tcp_send_events(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_EVENT_SYN_RESEND, TRUE);
    tcp_send_events(table, &flow, TRUE, SYN, 300, 0, 1000, 0, INET_TCP_EVENT_SYN_RESEND_DIFF_SEQ, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN, 300, 0, 1000, 0, INET_TCP_EVENT_SYN_WRONG_DIR, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 99, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND_DIFF_ACK, TRUE);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 600, 101, 1000, 0, INET_TCP_EVENT_SYNACK_RESEND_DIFF_SEQ, TRUE);
    tcp_send_events(table, &flow, TRUE, SYN_ACK, 100, 501, 1000, 0, INET_TCP_EVENT_SYNACK_WRONG_DIR, TRUE);
    /* RST outside and inside the window */
    tcp_send_events(table, &flow, FALSE, RST, 5000, 0, 0, 0, INET_TCP_EVENT_INVALID_RST, TRUE);
    tcp_send_ok(table, &flow, FALSE, RST, 501, 0, 0, 0, INET_TCP_STATE_CLOSED);
    /* Nothing is checked after the connection closes */
    tcp_send_ok(table, &flow, TRUE, ACK, 9999, 9999, 0, 10, INET_TCP_STATE_CLOSED);
    inet_flow_table_free(table);
}

void test_tcp_track_data_after_fin(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    flow = tcp_establish(table);
    tcp_send_ok(table, &flow, TRUE, FIN_ACK, 101, 501, 1000, 5, INET_TCP_STATE_FIN_WAIT1);
    /* The FIN sent again is not new data */
    tcp_send_events(table, &flow, TRUE, FIN_ACK, 101, 501, 1000, 5, INET_TCP_EVENT_RETRANSMISSION, FALSE);
    tcp_send_events(table, &flow, TRUE, ACK, 107, 501, 1000, 5, INET_TCP_EVENT_WRONG_SEQ, TRUE);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_FIN_WAIT1);
    inet_flow_table_free(table);
}

void test_tcp_track_window_scale(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    const guint8 client_opts[] = { OPT_NOP, TCP_OPT_WSCALE, 3, 2 };
    const guint8 server_opts[] = { OPT_NOP, TCP_OPT_WSCALE, 3, 3 };
    InetFlow *flow;

    tcp_test_setup(data);
    tcp_opts = client_opts;
    tcp_opts_len = sizeof(client_opts);
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_opts = server_opts;
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_opts = NULL;
    tcp_opts_len = 0;
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    /* A window of 100 from the server scales to 800 bytes */
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 101, 100, 0, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, TRUE, ACK, 101 + 700, 501, 1000, 10, INET_TCP_STATE_ESTABLISHED);
    tcp_send_events(table, &flow, TRUE, ACK, 101 + 900, 501, 1000, 10, INET_TCP_EVENT_OUT_OF_WINDOW, TRUE);
    inet_flow_table_free(table);

    /* Without a window scale option from both peers the window is not scaled */
    table = inet_flow_table_new();
    tcp_opts = client_opts;
    tcp_opts_len = sizeof(client_opts);
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_opts = NULL;
    tcp_opts_len = 0;
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 101, 100, 0, INET_TCP_STATE_ESTABLISHED);
    tcp_send_events(table, &flow, TRUE, ACK, 101 + 700, 501, 1000, 10, INET_TCP_EVENT_OUT_OF_WINDOW, TRUE);
    inet_flow_table_free(table);
}

void test_tcp_track_timestamps(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    guint8 ts_opts[] = { OPT_NOP, OPT_NOP, TCP_OPT_TIMESTAMP, 10, 0, 0, 0, 10, 0, 0, 0, 0 };
    InetFlow *flow;

    tcp_test_setup(data);
    tcp_opts = ts_opts;
    tcp_opts_len = sizeof(ts_opts);
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    ts_opts[7] = 50;
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    ts_opts[7] = 11;
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    ts_opts[7] = 12;
    tcp_send_ok(table, &flow, TRUE, ACK, 101, 501, 1000, 10, INET_TCP_STATE_ESTABLISHED);
    /* A timestamp older than the last one from the client */
    ts_opts[7] = 5;
    tcp_send_events(table, &flow, TRUE, ACK, 111, 501, 1000, 10, INET_TCP_EVENT_INVALID_TIMESTAMP, TRUE);
    /* The server timestamps are checked separately */
    ts_opts[7] = 51;
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 111, 1000, 0, INET_TCP_STATE_ESTABLISHED);
    /* A missing timestamp after both peers offered them */
    tcp_opts = NULL;
    tcp_opts_len = 0;
    tcp_send_events(table, &flow, TRUE, ACK, 111, 501, 1000, 10, INET_TCP_EVENT_INVALID_TIMESTAMP, TRUE);
    inet_flow_table_free(table);
}

void test_tcp_track_same_ports()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    /* With the same port at both ends the address identifies the client */
    tcp_test_setup(GUINT_TO_POINTER(ETH_PROTOCOL_IP));
    TEST_DPORT = TEST_SPORT;
    flow = tcp_establish(table);
    tcp_send_events(table, &flow, FALSE, SYN, 300, 0, 1000, 0, INET_TCP_EVENT_SYN_WRONG_DIR, TRUE);
    tcp_send_ok(table, &flow, FALSE, ACK, 501, 101, 1000, 10, INET_TCP_STATE_ESTABLISHED);
    TEST_DPORT = _TEST_DPORT;
    inet_flow_table_free(table);
}

void test_tcp_track_not_tcp()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;
    guint len;

    setup_test();
    len = make_udp_pkt(test_buffer, ETH_PROTOCOL_IP, 4);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET | INET_FLOW_TCP_TRACK, &pkt)));
    g_assert_false(pkt.tcp.invalid);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_NONE);
    inet_flow_table_free(table);
}

/* Send an IPv4 TCP segment between the given ends and track it */
static gboolean tcp_send_addr(InetFlowTable * table, InetFlow ** flow, guint32 saddr,
                              guint16 sport, guint32 daddr, guint16 dport, guint16 flags,
                              guint32 seq, guint32 ack, guint payload_len, InetPacket * pkt)
{
    guint8 *ip = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    guint8 *tcp = build_hdr_ipv4(ip, IP_PROTOCOL_TCP, FALSE);
    guint8 *p = build_tcp_segment(tcp, FALSE, flags, seq, ack, 1000, NULL) + payload_len;

    ((ip_hdr_t *) ip)->saddr = g_htonl(saddr);
    ((ip_hdr_t *) ip)->daddr = g_htonl(daddr);
    ((ip_hdr_t *) ip)->tot_len = g_htons(p - ip);
    ((tcp_hdr_t *) tcp)->source = g_htons(sport);
    ((tcp_hdr_t *) tcp)->destination = g_htons(dport);
    *flow = inet_flow_get(table, test_buffer, (guint) (p - test_buffer), 0, FLOW_GET | INET_FLOW_TCP_TRACK, pkt);
    g_assert_nonnull(*flow);
    return !pkt->tcp.invalid;
}

#define NAT_ADDR    0x0a0b0c0d
#define NAT_PORT    5555

/* Link the private flow to a public flow where the client is NAT_ADDR:NAT_PORT */
static InetFlow *tcp_link_public(InetFlowTable * table, InetFlow * private)
{
    guint32 server = g_htonl(TEST_DADDR), nat = g_htonl(NAT_ADDR);
    InetTuple tuple;
    InetFlow *public;

    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_TCP, &server, g_htons(TEST_DPORT), &nat, g_htons(NAT_PORT));
    public = inet_flow_lookup(table, &tuple) ? : inet_flow_create(table, &tuple, 0);
    g_assert_nonnull(public);
    inet_flow_tcp_link(private, public, &tuple.dst, tuple.dport);
    return public;
}

void test_tcp_link()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *private, *public, *flow;
    InetPacket pkt;

    setup_test();
    /* The client SYN on the private flow */
    g_assert_true(tcp_send_addr(table, &private, TEST_SADDR, TEST_SPORT, TEST_DADDR, TEST_DPORT, SYN, 100, 0, 0, &pkt));
    public = tcp_link_public(table, private);
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_SYN_SENT);

    /* The server SYN/ACK on the public flow */
    g_assert_true(tcp_send_addr(table, &flow, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, SYN_ACK, 500, 101, 0, &pkt));
    g_assert(flow == public);
    g_assert_cmphex(pkt.tcp.events, ==, 0);
    g_assert_cmpint(inet_flow_tcp_state(private), ==, INET_TCP_STATE_SYN_RECV);

    g_assert_true(tcp_send_addr(table, &flow, TEST_SADDR, TEST_SPORT, TEST_DADDR, TEST_DPORT, ACK, 101, 501, 10, &pkt));
    g_assert(flow == private);
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_ESTABLISHED);

    /* Data from the server is checked against the client data on the other flow */
    g_assert_true(tcp_send_addr(table, &flow, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, ACK, 501, 111, 20, &pkt));
    g_assert_cmphex(pkt.tcp.events, ==, 0);
    g_assert_false(tcp_send_addr(table, &flow, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, ACK, 521, 900, 0, &pkt));
    g_assert_cmphex(pkt.tcp.events, ==, INET_TCP_EVENT_INVALID_ACK);

    /* Each flow holds a reference to the shared state */
    inet_flow_free(private);
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_ESTABLISHED);
    inet_flow_table_free(table);
}

void test_tcp_link_replaces_state()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *private, *public, *flow;
    InetPacket pkt;

    setup_test();
    g_assert_true(tcp_send_addr(table, &private, TEST_SADDR, TEST_SPORT, TEST_DADDR, TEST_DPORT, SYN, 100, 0, 0, &pkt));
    /* The SYN/ACK arrives on the public flow before the flows are linked */
    g_assert_false(tcp_send_addr(table, &public, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, SYN_ACK, 500, 101, 0, &pkt));
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_ONE_SIDED);
    g_assert(tcp_link_public(table, private) == public);
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_SYN_SENT);
    g_assert_true(tcp_send_addr(table, &flow, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, SYN_ACK, 500, 101, 0, &pkt));
    g_assert_cmpint(inet_flow_tcp_state(private), ==, INET_TCP_STATE_SYN_RECV);
    inet_flow_table_free(table);
}

void test_tcp_link_before_syn()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *private, *public, *flow;
    InetPacket pkt;
    guint32 client = g_htonl(TEST_SADDR), server = g_htonl(TEST_DADDR);
    InetTuple tuple;

    setup_test();
    /* Link two flows before either has seen a packet */
    inet_tuple_set(&tuple, AF_INET, IP_PROTOCOL_TCP, &client, g_htons(TEST_SPORT), &server, g_htons(TEST_DPORT));
    g_assert_nonnull((private = inet_flow_create(table, &tuple, 0)));
    public = tcp_link_public(table, private);
    g_assert_cmpint(inet_flow_tcp_state(public), ==, INET_TCP_STATE_NONE);

    g_assert_true(tcp_send_addr(table, &flow, TEST_SADDR, TEST_SPORT, TEST_DADDR, TEST_DPORT, SYN, 100, 0, 0, &pkt));
    g_assert(flow == private);
    g_assert_true(tcp_send_addr(table, &flow, TEST_DADDR, TEST_DPORT, NAT_ADDR, NAT_PORT, SYN_ACK, 500, 101, 0, &pkt));
    g_assert(flow == public);
    g_assert_cmpint(inet_flow_tcp_state(private), ==, INET_TCP_STATE_SYN_RECV);
    inet_flow_table_free(table);
}

void test_tcp_track_handshake_paths(gconstpointer data)
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;

    tcp_test_setup(data);
    /* Simultaneous open: a SYN from each end */
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN, 500, 0, 1000, 0, INET_TCP_STATE_SYN_RECV);
    inet_flow_table_free(table);

    /* The client starts again with a new initial sequence number */
    table = inet_flow_table_new();
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, TRUE, SYN, 300, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_events(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_EVENT_SYNACK_WRONG_ACK, TRUE);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 301, 1000, 0, INET_TCP_STATE_SYN_RECV);
    inet_flow_table_free(table);

    /* The client aborts before the handshake completes */
    table = inet_flow_table_new();
    tcp_send_ok(table, &flow, TRUE, SYN, 100, 0, 1000, 0, INET_TCP_STATE_SYN_SENT);
    tcp_send_ok(table, &flow, FALSE, SYN_ACK, 500, 101, 1000, 0, INET_TCP_STATE_SYN_RECV);
    tcp_send_ok(table, &flow, TRUE, RST, 101, 0, 0, 0, INET_TCP_STATE_CLOSED);
    inet_flow_table_free(table);
}

void test_tcp_track_malformed()
{
    InetFlowTable *table = inet_flow_table_new();
    InetPacket pkt;
    InetFlow *flow;
    guint len;

    setup_test();
    /* A TCP header with a data offset below the minimum is not tracked */
    len = make_tcp_pkt(test_buffer, ETH_PROTOCOL_IP, FALSE, SYN, 100, 0, 1000, NULL);
    ((tcp_hdr_t *) (test_buffer + len - sizeof(tcp_hdr_t)))->flags = g_htons(0x4000 | SYN);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET | INET_FLOW_TCP_TRACK, &pkt)));
    g_assert_false(pkt.tcp.invalid);
    g_assert_cmpint(inet_flow_tcp_state(flow), ==, INET_TCP_STATE_NONE);
    inet_flow_table_free(table);
}

static int contexts_freed;

static void context_free(gpointer context)
{
    g_assert_cmpstr(context, ==, "context");
    contexts_freed++;
}

void test_table_context_free()
{
    InetFlowTable *table = inet_flow_table_new();
    InetFlow *flow;
    guint len;

    setup_test();
    contexts_freed = 0;
    inet_flow_table_context_free_set(table, context_free);

    /* Freeing a flow frees its context */
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    flow->context = "context";
    inet_flow_free(flow);
    g_assert_cmpint(contexts_freed, ==, 1);

    /* Freeing the table frees its flows and their contexts, in each state */
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    flow->context = "context";
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_TCP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    flow->context = "context";
    inet_flow_establish(table, flow);
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_ICMP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    flow->context = "context";
    inet_flow_close(table, flow);
    len = make_pkt(test_buffer, ETH_PROTOCOL_IPV6, IP_PROTOCOL_UDP);
    g_assert_nonnull(inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL));
    inet_flow_table_free(table);
    g_assert_cmpint(contexts_freed, ==, 4);

    /* Without a context free function the caller frees the contexts */
    table = inet_flow_table_new();
    inet_flow_table_context_free_set(table, context_free);
    inet_flow_table_context_free_set(table, NULL);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, 0, FLOW_GET, NULL)));
    flow->context = "context";
    inet_flow_table_free(table);
    g_assert_cmpint(contexts_freed, ==, 4);
}

void test_table_timeouts()
{
    InetFlowTable *table = inet_flow_table_new();
    guint64 ts = 1000;
    InetFlow *flow;
    guint len;

    setup_test();
    inet_flow_table_timeouts_set(table, 5, 50, 1);
    len = make_pkt(test_buffer, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP);
    g_assert_nonnull((flow = inet_flow_get(table, test_buffer, len, ts, FLOW_GET, NULL)));
    g_assert_cmpuint(inet_flow_table_size(table), ==, 1);

    /* A new flow uses the new timeout */
    g_assert_null(inet_flow_expire(table, ts + 4 * TIMESTAMP_RESOLUTION_US));
    g_assert(inet_flow_expire(table, ts + 5 * TIMESTAMP_RESOLUTION_US) == flow);

    /* An established flow uses the open timeout */
    inet_flow_establish(table, flow);
    g_assert_null(inet_flow_expire(table, ts + 49 * TIMESTAMP_RESOLUTION_US));
    g_assert(inet_flow_expire(table, ts + 50 * TIMESTAMP_RESOLUTION_US) == flow);

    /* A closed flow uses the closed timeout */
    inet_flow_close(table, flow);
    g_assert(inet_flow_expire(table, ts + 1 * TIMESTAMP_RESOLUTION_US) == flow);
    inet_flow_table_free(table);
}

void test_table_frag_limits()
{
    InetFlowTable *table = inet_flow_table_new();
    guint64 now = get_time_us();
    InetPacket pkt;
    int i;

    setup_test();
    inet_flow_table_frag_limits_set(table, 2, 5);
    for (i = 0; i < 2; i++)
        g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, 0, TRUE, 0, now, i, &pkt));
    g_assert_null(send_fragment(table, ETH_PROTOCOL_IP, 0, TRUE, 0, now, i, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_FRAG_UNTRACKED);

    /* Datagrams expire after the configured timeout */
    g_assert_nonnull(send_fragment(table, ETH_PROTOCOL_IP, 0, TRUE, 0, now + 6 * TIMESTAMP_RESOLUTION_US, i, &pkt));
    inet_flow_table_free(table);
}

void test_frag_list_standalone()
{
    InetFragList *fragments = inet_frag_list_new(1, 30);
    InetPacket pkt;
    guint8 *p;

    setup_test();
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 1);
    g_assert_true(inet_packet_parse(test_buffer, (guint) (p - test_buffer), INET_FLOW_L2, fragments, &pkt));

    /* The list holds one datagram */
    p = build_hdr_eth(test_buffer, ETH_PROTOCOL_IP);
    p = build_hdr_ip_fragment(p, ETH_PROTOCOL_IP, IP_PROTOCOL_UDP, FALSE, TRUE, 0, 2);
    g_assert_false(inet_packet_parse(test_buffer, (guint) (p - test_buffer), INET_FLOW_L2, fragments, &pkt));
    g_assert_cmpint(pkt.status, ==, INET_PACKET_FRAG_UNTRACKED);
    inet_frag_list_free(fragments);
}

int main(int argc, char *argv[])
{
    int rc;

    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/flow/parse/null/flow", test_flow_parse_null_flow);
    g_test_add_func("/flow/parse/null/buffer", test_flow_parse_null_buffer);
    g_test_add_func("/flow/parse/0/length", test_flow_parse_0_length);
    g_test_add_func("/flow/parse/less/eth/length", test_flow_parse_less_than_eth_length);
    g_test_add_func("/flow/parse/udp", test_flow_parse_udp);
    g_test_add_func("/flow/parse/tcp", test_flow_parse_tcp);
    g_test_add_func("/flow/parse/icmp", test_flow_parse_icmp);
    g_test_add_func("/flow/parse/pppoe", test_flow_parse_pppoe);
    g_test_add_func("/flow/parse/vlan", test_flow_parse_vlan);
    g_test_add_func("/flow/parse/mpls", test_flow_parse_mpls);
    g_test_add_func("/flow/parse/ipv6/ext", test_flow_parse_ipv6_ext);
    g_test_add_func("/flow/parse/gre", test_flow_parse_gre);
    g_test_add_func("/flow/parse/gre/no_tunnel_inspection", test_flow_parse_gre_no_tunnel_inspection);
    g_test_add_func("/flow/parse/unsuported/protocols/eth", test_flow_parse_unsupported_eth_protocols);
    g_test_add_func("/flow/parse/ipv6/no_ext", test_flow_parse_not_ipv6_ext);
    g_test_add_func("/flow/parse/unsuported/protocols/transport", test_flow_parse_unsupported_transport_protocols);
    g_test_add_func("/flow/parse/unsuported/protocols/ppp", test_flow_parse_unsupported_ppp_protocols);
    g_test_add_func("/flow/parse/vlan/more_than_2", test_flow_parse_more_than_2_vlan_tags);
    g_test_add_func("/flow/parse/malformed/vlan", test_flow_parse_malformed_vlan_hdr_length);
    g_test_add_func("/flow/parse/malformed/ipv4", test_flow_parse_malformed_ipv4_hdr_length);
    g_test_add_func("/flow/parse/ipv4/options", test_flow_parse_ipv4_options);
    g_test_add_func("/flow/parse/malformed/ipv4/hlen", test_flow_parse_malformed_ipv4_hlen);
    g_test_add_func("/flow/parse/malformed/ipv6", test_flow_parse_malformed_ipv6_hdr_length);
    g_test_add_func("/flow/parse/malformed/pppoe", test_flow_parse_malformed_pppoe_hdr_length);
    g_test_add_func("/flow/parse/malformed/tcp", test_flow_parse_malformed_tcp_hdr_length);
    g_test_add_func("/flow/parse/malformed/udp", test_flow_parse_malformed_udp_hdr_length);
    g_test_add_func("/flow/parse/malformed/icmp", test_flow_parse_malformed_icmp_hdr_length);
    g_test_add_func("/flow/parse/malformed/ipv6_ext/hbh", test_flow_parse_malformed_ipv6_ext_hbh_length);
    g_test_add_func("/flow/parse/malformed/ipv6_ext/frag", test_flow_parse_malformed_ipv6_ext_frag_length);
    g_test_add_func("/flow/parse/malformed/ipv6_ext/auth", test_flow_parse_malformed_ipv6_ext_auth_length);
    g_test_add_func("/flow/parse/malformed/ipv6_ext/sctp", test_flow_parse_malformed_ipv6_ext_sctp_length);
    g_test_add_func("/flow/properties", test_flow_properties);
    g_test_add_func("/flow/properties/reversed", test_flow_properties_reversed);
    g_test_add_func("/flow/properties/ipv6", test_flow_properties_ipv6);
    g_test_add_func("/flow/properties/ipv6/reversed", test_flow_properties_ipv6_reversed);
    g_test_add_func("/flow/properties/table", test_flow_table_properties);
    g_test_add_func("/flow/foreach", test_flow_foreach);
    g_test_add_func("/flow/create", test_flow_create);
    g_test_add_func("/flow/create/many", test_flow_create_many);
    g_test_add_func("/flow/table/size", test_flow_table_size);
    g_test_add_func("/flow/not_expired", test_flow_not_expired);
    g_test_add_func("/flow/expired", test_flow_expired);
    g_test_add_func("/flow/expired/no_unref", test_flow_expired_no_unref);
    g_test_add_func("/flow/expired/only_once", test_flow_expired_only_once);
    g_test_add_func("/flow/tcp/new", test_flow_tcp_new);
    g_test_add_func("/flow/tcp/update", test_flow_tcp_update);
    g_test_add_func("/flow/tcp/state/basic", test_flow_tcp_state_basic);
    g_test_add_func("/flow/tcp/state/syn_rst", test_flow_tcp_state_syn_rst);
    g_test_add_func("/flow/tcp/state/syn_synack_rst", test_flow_tcp_state_syn_synack_rst);
    g_test_add_func("/flow/tcp/state/fin_rst", test_flow_tcp_state_fin_rst);
    g_test_add_func("/flow/tcp/state/syn_timeout", test_flow_tcp_state_syn_timeout);
    g_test_add_func("/flow/tcp/state/syn_synack_timeout", test_flow_tcp_state_syn_synack_timeout);
    g_test_add_func("/flow/tcp/state/fin_timeout", test_flow_tcp_state_fin_timeout);
    g_test_add_func("/flow/ipv4_encap", test_flow_ipv4_encap);
    g_test_add_func("/flow/ipv6_encap", test_flow_ipv6_encap);
    g_test_add_func("/flow/bad/ip_version", test_flow_bad_ip_version);
    g_test_add_func("/flow/parse/ipv4/fragment", test_flow_parse_ipv4_fragment);
    g_test_add_func("/flow/parse/ipv6/fragment", test_flow_parse_ipv6_fragment);
    g_test_add_func("/flow/table/free_fragments", test_flow_table_free_fragments);
    g_test_add_data_func("/flow/fragment/direction/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_flow_fragment_direction);
    g_test_add_data_func("/flow/direction/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_flow_direction);
    g_test_add_data_func("/flow/direction/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_flow_direction);
    g_test_add_data_func("/flow/fragment/direction/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_flow_fragment_direction);
    g_test_add_func("/clear/expired_frag_info", test_clear_expired_frag_info);
    g_test_add_func("/flow/expiry/queue", test_flow_expiry_queue);
    g_test_add_func("/flow/match/udp", test_flow_match_udp);
    g_test_add_func("/flow/match/udp6", test_flow_match_udp6);
    g_test_add_func("/tuple/equal/family", test_tuple_equal_family);
    g_test_add_data_func("/flow/match/same_ports/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_flow_match_same_ports);
    g_test_add_data_func("/flow/match/same_ports/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_flow_match_same_ports);
    g_test_add_func("/flow/match/tcp", test_flow_match_tcp);
    g_test_add_func("/flow/match/tcp6", test_flow_match_tcp6);
    g_test_add_func("/flow/match/icmp", test_flow_match_icmp);
    g_test_add_func("/flow/match/icmp6", test_flow_match_icmp6);
    g_test_add_func("/flow/nomatch/port", test_flow_nomatch_port);

    g_test_add_func("/tuple/exact", test_tuple_exact);
    g_test_add_func("/flow/parse/gre/options", test_flow_parse_gre_options);
    g_test_add_func("/flow/parse/ip_in_ipv6", test_flow_parse_ip_in_ipv6);
    g_test_add_func("/flow/parse/ip_in_ipv4", test_flow_parse_ip_in_ipv4);
    g_test_add_func("/flow/parse/sctp/ipv4", test_flow_parse_sctp_ipv4);
    g_test_add_func("/flow/parse/tunnel_depth", test_flow_parse_tunnel_depth);
    g_test_add_func("/flow/parse/tunnel_depth/gre", test_flow_parse_tunnel_depth_gre);
    g_test_add_func("/packet/parse", test_packet_parse);
    g_test_add_func("/packet/l3", test_packet_l3);
    g_test_add_func("/packet/tuple", test_packet_tuple);
    g_test_add_func("/flow/get/parse_fail", test_flow_get_full_parse_fail);
    g_test_add_func("/flow/create_lookup", test_flow_create_lookup);
    g_test_add_func("/flow/create/existing", test_flow_create_existing);
    g_test_add_func("/flow/establish_close", test_flow_establish_close);
    g_test_add_data_func("/flow/fragment/limit/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_flow_fragment_limit);
    g_test_add_data_func("/flow/fragment/limit/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_flow_fragment_limit);

    g_test_add_func("/tuple/equal/mismatch", test_tuple_equal_mismatch);
    g_test_add_func("/tuple/hash", test_tuple_hash);
    g_test_add_func("/tuple/equal/directions", test_tuple_equal_directions);
    g_test_add_func("/flow/fragment/mismatch", test_flow_fragment_mismatch);
    g_test_add_func("/flow/fragment/atomic", test_flow_fragment_atomic);
    g_test_add_func("/flow/parse/malformed/gre", test_flow_parse_malformed_gre);
    g_test_add_func("/flow/parse/malformed/ipv4_tcp", test_flow_parse_malformed_ipv4_tcp);
    g_test_add_func("/flow/parse/malformed/auth", test_flow_parse_malformed_auth_length);
    g_test_add_func("/flow/parse/malformed/mpls", test_flow_parse_malformed_mpls);
    g_test_add_func("/flow/parse/malformed/pppoe_hdr", test_flow_parse_malformed_pppoe);
    g_test_add_func("/flow/foreach/null", test_flow_foreach_null);

    g_test_add_data_func("/tuple/set/ipv4", GUINT_TO_POINTER(AF_INET), test_tuple_set_sockaddr);
    g_test_add_data_func("/tuple/set/ipv6", GUINT_TO_POINTER(AF_INET6), test_tuple_set_sockaddr);
    g_test_add_func("/tuple/server_client", test_tuple_server_client);
    g_test_add_func("/tuple/exact/ports", test_tuple_exact_ports);

    g_test_add_data_func("/packet/tcp/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_packet_tcp);
    g_test_add_data_func("/packet/tcp/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_packet_tcp);
    g_test_add_data_func("/packet/padding/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_packet_padding);
    g_test_add_data_func("/packet/padding/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_packet_padding);
    g_test_add_func("/packet/jumbogram", test_packet_jumbogram);
    g_test_add_func("/packet/udp", test_packet_udp);
    g_test_add_func("/packet/ipv6/ext", test_packet_ipv6_ext);
    g_test_add_data_func("/packet/fragment/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_packet_fragment);
    g_test_add_data_func("/packet/fragment/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_packet_fragment);
    g_test_add_func("/flow/get/not_found", test_flow_get_not_found);
    g_test_add_func("/flow/get/table_full", test_flow_get_table_full);

    g_test_add_func("/anomaly/none", test_anomaly_none);
    g_test_add_func("/anomaly/ip_version", test_anomaly_ip_version);
    g_test_add_func("/anomaly/ipv4", test_anomaly_ipv4);
    g_test_add_func("/anomaly/ipv6", test_anomaly_ipv6);
    g_test_add_data_func("/anomaly/tcp/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_anomaly_tcp);
    g_test_add_data_func("/anomaly/tcp/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_anomaly_tcp);
    g_test_add_data_func("/anomaly/udp/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_anomaly_udp);
    g_test_add_data_func("/anomaly/udp/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_anomaly_udp);
    g_test_add_func("/anomaly/udp/fragment", test_anomaly_udp_fragment);

    g_test_add_func("/tcp/options", test_tcp_options);
    g_test_add_func("/tcp/options/invalid", test_tcp_options_invalid);
    g_test_add_func("/tcp/options/not_validated", test_options_not_validated);
    g_test_add_func("/ipv4/options/invalid", test_ipv4_options_invalid);

    g_test_add_data_func("/fragment/overlap/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_overlap);
    g_test_add_data_func("/fragment/overlap/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_overlap);
    g_test_add_data_func("/fragment/many/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_many_datagrams);
    g_test_add_data_func("/fragment/many/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_many_datagrams);
    g_test_add_data_func("/fragment/expiry_order/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_expiry_order);
    g_test_add_data_func("/fragment/expiry_order/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_expiry_order);
    g_test_add_data_func("/fragment/too_large/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_too_large);
    g_test_add_data_func("/fragment/too_large/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_too_large);
    g_test_add_data_func("/fragment/out_of_order/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_out_of_order);
    g_test_add_data_func("/fragment/out_of_order/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_out_of_order);
    g_test_add_func("/fragment/last_first", test_fragment_last_first);
    g_test_add_func("/fragment/expired", test_fragment_expired);

    g_test_add_func("/fragment/many_ranges", test_fragment_many_ranges);
    g_test_add_data_func("/fragment/no_list/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_fragment_no_list);
    g_test_add_data_func("/fragment/no_list/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_fragment_no_list);

    g_test_add_data_func("/tcp/track/client_close/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_client_close);
    g_test_add_data_func("/tcp/track/client_close/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_client_close);
    g_test_add_data_func("/tcp/track/server_close/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_server_close);
    g_test_add_data_func("/tcp/track/server_close/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_server_close);
    g_test_add_data_func("/tcp/track/simultaneous_close/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_simultaneous_close);
    g_test_add_data_func("/tcp/track/simultaneous_close/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_simultaneous_close);
    g_test_add_data_func("/tcp/track/untracked/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_untracked);
    g_test_add_data_func("/tcp/track/reuse/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_reuse);
    g_test_add_data_func("/tcp/track/reuse/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_reuse);
    g_test_add_data_func("/tcp/track/untracked/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_untracked);
    g_test_add_data_func("/tcp/track/one_sided/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_one_sided);
    g_test_add_data_func("/tcp/track/one_sided/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_one_sided);
    g_test_add_data_func("/tcp/track/handshake_errors/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_handshake_errors);
    g_test_add_data_func("/tcp/track/handshake_errors/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_handshake_errors);
    g_test_add_data_func("/tcp/track/handshake_rst/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_handshake_rst);
    g_test_add_data_func("/tcp/track/handshake_rst/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_handshake_rst);
    g_test_add_data_func("/tcp/track/established/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_established);
    g_test_add_data_func("/tcp/track/established/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_established);
    g_test_add_data_func("/tcp/track/data_after_fin/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_data_after_fin);
    g_test_add_data_func("/tcp/track/data_after_fin/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_data_after_fin);
    g_test_add_data_func("/tcp/track/window_scale/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_window_scale);
    g_test_add_data_func("/tcp/track/window_scale/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_window_scale);
    g_test_add_data_func("/tcp/track/timestamps/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_timestamps);
    g_test_add_data_func("/tcp/track/timestamps/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_timestamps);
    g_test_add_func("/tcp/track/same_ports", test_tcp_track_same_ports);
    g_test_add_func("/tcp/track/not_tcp", test_tcp_track_not_tcp);
    g_test_add_func("/tcp/link", test_tcp_link);
    g_test_add_func("/tcp/link/replaces_state", test_tcp_link_replaces_state);
    g_test_add_func("/tcp/link/before_syn", test_tcp_link_before_syn);

    g_test_add_data_func("/tcp/track/handshake_paths/ipv4", GUINT_TO_POINTER(ETH_PROTOCOL_IP), test_tcp_track_handshake_paths);
    g_test_add_data_func("/tcp/track/handshake_paths/ipv6", GUINT_TO_POINTER(ETH_PROTOCOL_IPV6), test_tcp_track_handshake_paths);
    g_test_add_func("/tcp/track/malformed", test_tcp_track_malformed);

    g_test_add_func("/table/context_free", test_table_context_free);
    g_test_add_func("/table/timeouts", test_table_timeouts);
    g_test_add_func("/table/frag_limits", test_table_frag_limits);
    g_test_add_func("/table/hash/portless", test_table_hash_portless);
    g_test_add_func("/table/hash/stored", test_table_hash_stored);
    g_test_add_func("/table/hash/seed", test_table_hash_seed);
    g_test_add_func("/frag_list/standalone", test_frag_list_standalone);

    rc = g_test_run();
    return rc;
}
