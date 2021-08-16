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
typedef struct _InetTuple {
    struct sockaddr_storage src;
    struct sockaddr_storage dst;
    guint16 protocol;
    guint hash;
} InetTuple;

#define inet_tuple_get_src_port(tuple) ((struct sockaddr_in *) &(tuple)->src)->sin_port
#define inet_tuple_get_dst_port(tuple) ((struct sockaddr_in *) &(tuple)->dst)->sin_port
struct sockaddr_storage *inet_tuple_get_lower(InetTuple * tuple);
struct sockaddr_storage *inet_tuple_get_upper(InetTuple * tuple);
#define inet_tuple_get_server inet_tuple_get_lower
#define inet_tuple_get_client inet_tuple_get_upper
gboolean inet_tuple_equal(InetTuple * a, InetTuple * b);
gboolean inet_tuple_exact(InetTuple * a, InetTuple * b);
#define inet_tuple_get_protocol(tuple) (tuple)->protocol
#define inet_tuple_set_protocol(tuple, proto) (tuple)->protocol = proto
guint inet_tuple_hash(InetTuple * t);

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
    guint16 hash;
    guint16 flags;
    guint8 direction;
    guint16 server_port;
    guint32 server_ip[4];
    InetTuple tuple;
    gpointer context;
} InetFlow;

#define inet_flow_protocol(flow) flow->tuple.protocol
void inet_flow_unref(InetFlow * flow);

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
InetTuple *inet_flow_parse(const guint8 * frame, guint length, InetFragList * fragments,
                           InetTuple * result, gboolean inspect_tunnel);
InetTuple *inet_flow_parse_ip(const guint8 * iphdr, guint length, InetFragList * fragments,
                              InetTuple * result, gboolean inspect_tunnel);
InetFlow *inet_flow_lookup(InetFlowTable * table, InetTuple * tuple);
InetFlow *inet_flow_get(InetFlowTable * table, const guint8 * frame, guint length);
InetFlow *inet_flow_get_full(InetFlowTable * table, const guint8 * frame,
                             guint length, guint16 hash, guint64 timestamp,
                             gboolean update, gboolean l2, gboolean inspect_tunnel,
                             const uint8_t ** iphr, InetTuple **);
InetFlow *inet_flow_create(InetFlowTable * table, InetTuple * tuple, uint64_t timestamp);
InetFlow *inet_flow_expire(InetFlowTable * table, guint64 ts);
void inet_flow_establish(InetFlowTable * table, InetFlow * flow);
void inet_flow_close(InetFlowTable * table, InetFlow * flow);
typedef void (*IFFunc)(InetFlow * flow, gpointer user_data);
void inet_flow_foreach(InetFlowTable * table, IFFunc func, gpointer user_data);
void inet_flow_table_unref(InetFlowTable * table);

#endif                          /* __INET_FLOW_H__ */
