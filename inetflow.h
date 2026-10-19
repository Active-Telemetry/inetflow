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
#ifndef __INET_FLOW_H__
#define __INET_FLOW_H__
#include <glib.h>
#include <netinet/in.h>

/* Flow states */
typedef enum {
    FLOW_NEW,
    FLOW_OPEN,
    FLOW_CLOSED,
} InetFlowState;

/* Flow Directions */
typedef enum {
    FLOW_DIRECTION_UNKNOWN,
    FLOW_DIRECTION_ORIGINAL,
    FLOW_DIRECTION_REPLY,
} InetFlowDirection;

/* Default timeouts */
#define INET_FLOW_DEFAULT_NEW_TIMEOUT         30
#define INET_FLOW_DEFAULT_OPEN_TIMEOUT        300
#define INET_FLOW_DEFAULT_CLOSED_TIMEOUT      10

/* InetTuple */
typedef union _InetAddr {
    struct in_addr v4;
    struct in6_addr v6;
    guint8 bytes[16];
} InetAddr;

typedef struct _InetTuple {
    InetAddr src;               /* IPv4 uses the first 4 bytes */
    InetAddr dst;
    guint16 sport;              /* Network byte order */
    guint16 dport;              /* Network byte order */
    guint8 family;              /* AF_INET or AF_INET6 */
    guint8 protocol;
    guint16 offset;             /* Offset of the transport header in the frame */
    guint32 hash;
} InetTuple;

#define inet_tuple_family(tuple) (tuple)->family
#define inet_tuple_get_protocol(tuple) (tuple)->protocol
#define inet_tuple_set_protocol(tuple, proto) (tuple)->protocol = proto
#define inet_tuple_get_src_port(tuple) (tuple)->sport
#define inet_tuple_get_dst_port(tuple) (tuple)->dport
void inet_tuple_set(InetTuple * tuple, guint8 family, guint8 protocol, const void *src,
                    guint16 sport, const void *dst, guint16 dport);
const InetAddr *inet_tuple_server_addr(const InetTuple * tuple);
guint16 inet_tuple_server_port(const InetTuple * tuple);
const InetAddr *inet_tuple_client_addr(const InetTuple * tuple);
guint16 inet_tuple_client_port(const InetTuple * tuple);
void inet_tuple_to_sockaddr(const InetTuple * tuple, gboolean src,
                            struct sockaddr_storage *out);
gboolean inet_tuple_equal(const InetTuple * a, const InetTuple * b);
gboolean inet_tuple_exact(const InetTuple * a, const InetTuple * b);
guint inet_tuple_hash(InetTuple * tuple);

/* InetFragList */
#define INET_FRAG_DEFAULT_MAX                 128
#define INET_FRAG_DEFAULT_TIMEOUT             30
typedef struct _InetFragList InetFragList;
InetFragList *inet_frag_list_new(guint max_datagrams, guint timeout_s);
void inet_frag_list_free(InetFragList * fragments);

/* InetFlow */
typedef struct _InetFlow {
    InetTuple tuple;            /* The tuple of the first packet */
    InetFlowState state;
    guint8 direction;           /* InetFlowDirection of the last packet */
    guint64 timestamp;          /* Time of the last packet */
    guint64 packets;
    guint64 inbytes;            /* Reply direction */
    guint64 outbytes;           /* Original direction */
    gpointer context;           /* Freed by the table context_free callback */
} InetFlow;

#define inet_flow_protocol(flow) (flow)->tuple.protocol
void inet_flow_free(InetFlow * flow);

/* Flags for inet_flow_get() and inet_packet_parse() */
typedef enum {
    INET_FLOW_L2 = 1 << 0,      /* The frame starts with Ethernet, else IP */
    INET_FLOW_TUNNEL = 1 << 1,  /* Parse into GRE and IP in IP tunnels */
    INET_FLOW_CREATE = 1 << 2,  /* Create the flow if it does not exist */
    INET_FLOW_UPDATE = 1 << 3,  /* Update the flow state, counters and expiry */
    INET_FLOW_VALIDATE = 1 << 4,        /* Check IP and TCP options */
    INET_FLOW_TCP_TRACK = 1 << 5,       /* Track TCP connections, implies VALIDATE */
} InetFlowFlags;

/* InetPacket status */
typedef enum {
    INET_PACKET_OK,
    INET_PACKET_PARSE_ERROR,    /* The frame could not be parsed */
    INET_PACKET_NOT_FOUND,      /* No flow, and INET_FLOW_CREATE was not set */
    INET_PACKET_TABLE_FULL,     /* No flow, and the table is full */
    INET_PACKET_FRAG_UNTRACKED, /* The fragment list is full */
} InetPacketStatus;

/* Header anomalies reported in InetPacket.anomalies */
#define INET_ANOMALY_IP_VERSION             (1 << 0)    /* IP version is not 4 or 6 */
#define INET_ANOMALY_IPV4_TRUNCATED         (1 << 1)    /* Frame ends inside the IPv4 packet */
#define INET_ANOMALY_IPV4_HLEN_TOO_SMALL    (1 << 2)    /* IHL is less than 5 */
#define INET_ANOMALY_IPV4_LEN_TOO_SMALL     (1 << 3)    /* Total length is less than the IHL */
#define INET_ANOMALY_IPV6_TRUNCATED         (1 << 4)    /* Frame ends inside the IPv6 packet */
#define INET_ANOMALY_IPV6_EXTHDR_TRUNCATED  (1 << 5)    /* Extension header extends past the packet */
#define INET_ANOMALY_TCP_TRUNCATED          (1 << 6)    /* TCP header extends past the packet */
#define INET_ANOMALY_TCP_HLEN_TOO_SMALL     (1 << 7)    /* TCP data offset is less than 5 */
#define INET_ANOMALY_UDP_TRUNCATED          (1 << 8)    /* UDP header extends past the packet */
#define INET_ANOMALY_UDP_LEN_INVALID        (1 << 9)    /* UDP length is less than 8 or too long */
#define INET_ANOMALY_IPV4_OPT_INVALID       (1 << 10)   /* IPv4 option length is invalid */
#define INET_ANOMALY_TCP_OPT_INVALID        (1 << 11)   /* TCP option length is invalid */
#define INET_ANOMALY_TCP_OPT_DUPLICATE      (1 << 12)   /* TCP option appears more than once */
#define INET_ANOMALY_FRAG_OVERLAP           (1 << 13)   /* Fragment overlaps data already seen */
#define INET_ANOMALY_FRAG_TOO_LARGE         (1 << 14)   /* Fragment ends past the maximum IP length */
#define INET_ANOMALY_FRAG_LIMIT             (1 << 15)   /* Datagram not tracked, the list is full */
#define INET_ANOMALY_FRAG_EXPIRED           (1 << 16)   /* Datagram tracking timed out */

/* TCP options reported in InetPacket.tcp.options */
#define INET_TCP_OPT_MSS                    (1 << 0)
#define INET_TCP_OPT_WSCALE                 (1 << 1)
#define INET_TCP_OPT_SACK_PERMITTED         (1 << 2)
#define INET_TCP_OPT_SACK                   (1 << 3)
#define INET_TCP_OPT_TIMESTAMP              (1 << 4)

/* TCP connection states reported in InetPacket.tcp.state */
typedef enum {
    INET_TCP_STATE_NONE,        /* No packet has been tracked */
    INET_TCP_STATE_UNTRACKED,   /* First seen after the handshake, so not tracked */
    INET_TCP_STATE_ONE_SIDED,   /* Only one direction of the handshake was seen */
    INET_TCP_STATE_SYN_SENT,
    INET_TCP_STATE_SYN_RECV,
    INET_TCP_STATE_ESTABLISHED,
    INET_TCP_STATE_FIN_WAIT1,
    INET_TCP_STATE_FIN_WAIT2,
    INET_TCP_STATE_CLOSING,
    INET_TCP_STATE_TIME_WAIT,
    INET_TCP_STATE_CLOSE_WAIT,
    INET_TCP_STATE_LAST_ACK,
    INET_TCP_STATE_CLOSED,
} InetTcpConnState;

/* TCP events reported in InetPacket.tcp.events */
#define INET_TCP_EVENT_ONE_SIDED            (1 << 0)    /* Only one direction is seen */
#define INET_TCP_EVENT_SYN_WRONG_DIR        (1 << 1)    /* SYN from the server */
#define INET_TCP_EVENT_SYNACK_WRONG_DIR     (1 << 2)    /* SYN/ACK from the client */
#define INET_TCP_EVENT_ACK_WRONG_DIR        (1 << 3)    /* Server ACK before the handshake ends */
#define INET_TCP_EVENT_SYN_RESEND           (1 << 4)    /* SYN sent again (valid in handshake) */
#define INET_TCP_EVENT_SYN_RESEND_DIFF_SEQ  (1 << 5)    /* SYN sent again with another sequence */
#define INET_TCP_EVENT_SYNACK_RESEND        (1 << 6)    /* SYN/ACK sent again (valid in handshake) */
#define INET_TCP_EVENT_SYNACK_RESEND_DIFF_ACK (1 << 7)  /* SYN/ACK sent again with another ACK */
#define INET_TCP_EVENT_SYNACK_RESEND_DIFF_SEQ (1 << 8)  /* SYN/ACK sent again with another sequence */
#define INET_TCP_EVENT_SYNACK_WRONG_ACK     (1 << 9)    /* SYN/ACK does not acknowledge the SYN */
#define INET_TCP_EVENT_WRONG_SEQ            (1 << 10)   /* Sequence number is not the expected one */
#define INET_TCP_EVENT_INVALID_ACK          (1 << 11)   /* ACK for data that has not been sent */
#define INET_TCP_EVENT_RIGHT_SEQ_WRONG_ACK  (1 << 12)   /* Handshake ACK has the wrong ACK number */
#define INET_TCP_EVENT_OUT_OF_WINDOW        (1 << 13)   /* Data beyond the receive window */
#define INET_TCP_EVENT_INVALID_RST          (1 << 14)   /* RST outside the receive window */
#define INET_TCP_EVENT_INVALID_TIMESTAMP    (1 << 15)   /* Timestamp missing or older than the last */
#define INET_TCP_EVENT_RETRANSMISSION       (1 << 16)   /* Data sent again (valid) */
#define INET_TCP_EVENT_BEFORE_LAST_ACK      (1 << 17)   /* Data already acknowledged (valid) */

/* InetPacket */
typedef struct _InetPacket {
    InetPacketStatus status;
    InetTuple tuple;
    const guint8 *l3;           /* IP header */
    const guint8 *l4;           /* Transport header, or NULL for non-first fragments */
    const guint8 *payload;      /* Transport payload for TCP, UDP and SCTP, or NULL */
    guint32 payload_length;     /* Bytes of payload, excluding link layer padding */
    guint8 direction;           /* InetFlowDirection, set when the flow is updated */
    gboolean fragment;          /* The packet is a fragment of a larger datagram */
    guint32 anomalies;          /* INET_ANOMALY_ flags for malformed headers */
    struct {
        guint16 flags;          /* FIN is bit 0, NS is bit 8 */
        guint16 window;         /* Not scaled */
        guint32 seq;            /* Host byte order */
        guint32 ack;            /* Host byte order */
        guint8 options;         /* INET_TCP_OPT_ flags, with INET_FLOW_VALIDATE */
        guint8 wscale;          /* Window scale option */
        guint16 mss;            /* Maximum segment size option */
        guint32 ts_val;         /* Timestamp option value */
        guint32 ts_ecr;         /* Timestamp option echo reply */
        InetTcpConnState state; /* Connection state before the packet, with TCP_TRACK */
        guint32 events;         /* INET_TCP_EVENT_ flags, with INET_FLOW_TCP_TRACK */
        gboolean invalid;       /* Invalid for the connection state, with TCP_TRACK */
    } tcp;
} InetPacket;

/* InetFlowTable */
typedef struct _InetFlowTable InetFlowTable;
InetFlowTable *inet_flow_table_new(GDestroyNotify context_free);
void inet_flow_table_free(InetFlowTable * table);
guint inet_flow_table_size(InetFlowTable * table);
void inet_flow_table_max_set(InetFlowTable * table, guint64 max_flows);
void inet_flow_table_timeouts_set(InetFlowTable * table, guint new_s, guint open_s,
                                  guint closed_s);
void inet_flow_table_frag_limits_set(InetFlowTable * table, guint max_datagrams,
                                     guint timeout_s);

gboolean inet_packet_parse(const guint8 * frame, guint length, guint32 flags,
                           InetFragList * fragments, InetPacket * pkt);
InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length,
                        guint64 timestamp, guint32 flags, InetPacket * pkt);
InetFlow *inet_flow_lookup(InetFlowTable * table, const InetTuple * tuple);
InetFlow *inet_flow_create(InetFlowTable * table, const InetTuple * tuple,
                           guint64 timestamp);
InetFlow *inet_flow_expire(InetFlowTable * table, guint64 timestamp);
void inet_flow_establish(InetFlowTable * table, InetFlow * flow);
void inet_flow_close(InetFlowTable * table, InetFlow * flow);
typedef void (*IFFunc)(InetFlow * flow, gpointer user_data);
void inet_flow_foreach(InetFlowTable * table, IFFunc func, gpointer user_data);

InetTcpConnState inet_flow_tcp_state(InetFlow * flow);
void inet_flow_tcp_link(InetFlow * flow, InetFlow * linked, const InetAddr * client,
                        guint16 client_port);

#endif                          /* __INET_FLOW_H__ */
