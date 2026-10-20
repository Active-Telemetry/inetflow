/* InetFlow - libFuzzer harness
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
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>
 */

/* The first byte of each input selects the parse flags and the rest is the
 * frame. The flow table and the fragment list persist between inputs, so
 * that later inputs match flows, fragments and TCP state from earlier ones.
 * The table size is limited, and flows expire as the time advances, so that
 * a long run does not grow without bound. */
#include "inetflow.h"

#define FUZZ_FLAGS (INET_FLOW_L2 | INET_FLOW_TUNNEL | INET_FLOW_VALIDATE | INET_FLOW_TCP_TRACK)

static InetFlowTable *table;
static InetFragList *fragments;
static guint64 now = 1;

int LLVMFuzzerTestOneInput(const guint8 * data, size_t size)
{
    guint32 flags;
    InetPacket pkt;
    InetFlow *flow;

    if (size < 1)
        return 0;
    if (!table) {
        table = inet_flow_table_new();
        inet_flow_table_max_set(table, 4096);
        fragments = inet_frag_list_new(64, 1);
    }
    flags = data[0] & FUZZ_FLAGS;
    now += 1000;

    inet_flow_get(table, data + 1, size - 1, now, flags | INET_FLOW_CREATE | INET_FLOW_UPDATE, &pkt);
    inet_packet_parse(data + 1, size - 1, flags, fragments, &pkt);
    while ((flow = inet_flow_expire(table, now)))
        inet_flow_free(flow);
    return 0;
}
