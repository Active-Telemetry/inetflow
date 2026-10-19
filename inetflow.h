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
#define INET_FLOW_LIFETIME_COUNT              3

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
typedef struct _InetFragment {
    guint32 id;
    InetTuple tuple;
    guint64 timestamp;
} InetFragment;
typedef struct _InetFragList {
    GRWLock lock;
    GList *head;
} InetFragList;

InetFragList *inet_frag_list_new();
void inet_frag_list_free(InetFragList * finished);
gboolean inet_frag_list_update(InetFragList * fragments, InetFragment * entry,
                               gboolean more_fragments);

/* InetFlow */
typedef struct _InetFlow {
    struct _InetFlowTable *table;
    GList list;
    guint64 timestamp;
    guint64 lifetime;
    guint64 packets;
    InetFlowState state;
    guint family;
    guint32 hash;
    guint16 flags;
    guint8 direction;
    guint16 server_port;
    guint32 server_ip[4];
    InetTuple tuple;
    gpointer context;
    guint64 inbytes;
    guint64 outbytes;
} InetFlow;

#define inet_flow_protocol(flow) flow->tuple.protocol
void inet_flow_unref(InetFlow * flow);

/* Flags for inet_flow_get() and inet_packet_parse() */
typedef enum {
    INET_FLOW_L2 = 1 << 0,      /* The frame starts with Ethernet, else IP */
    INET_FLOW_TUNNEL = 1 << 1,  /* Parse into GRE and IP in IP tunnels */
    INET_FLOW_CREATE = 1 << 2,  /* Create the flow if it does not exist */
    INET_FLOW_UPDATE = 1 << 3,  /* Update the flow state, counters and expiry */
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
    } tcp;
} InetPacket;

/* InetFlowTable */
typedef struct _InetFlowTable {
    GHashTable *table;
    GQueue *expire_queue[INET_FLOW_LIFETIME_COUNT];
    InetFragList *frag_info_list;
    guint64 hits;
    guint64 misses;
    guint64 max;
} InetFlowTable;

InetFlowTable *inet_flow_table_new(void);
#define inet_flow_table_size(table) g_hash_table_size(table->table)
void inet_flow_table_max_set(InetFlowTable * table, guint64 value);
gboolean inet_packet_parse(const guint8 * frame, guint length, guint32 flags,
                           InetFragList * fragments, InetPacket * pkt);
InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length,
                        guint64 timestamp, guint32 flags, InetPacket * pkt);
InetFlow *inet_flow_lookup(InetFlowTable * table, InetTuple * tuple);
InetFlow *inet_flow_create(InetFlowTable * table, InetTuple * tuple, uint64_t timestamp);
InetFlow *inet_flow_expire(InetFlowTable * table, guint64 ts);
void inet_flow_establish(InetFlowTable * table, InetFlow * flow);
void inet_flow_close(InetFlowTable * table, InetFlow * flow);
typedef void (*IFFunc)(InetFlow * flow, gpointer user_data);
void inet_flow_foreach(InetFlowTable * table, IFFunc func, gpointer user_data);
void inet_flow_table_unref(InetFlowTable * table);

#endif                          /* __INET_FLOW_H__ */
