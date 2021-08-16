/* inetflow - IP Flow Manager demo code
 * LD_LIBRARY_PATH=. ./demo -p test.pcap -d
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
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
#include "ndpi/ndpi_api.h"
#endif
#include <glib.h>
#include <glib/gprintf.h>
#include "inetflow.h"

static gboolean dpi = FALSE;
static gchar *filename = NULL;
static gboolean verbose = FALSE;
static gint frames = 0;
static InetFlowTable *table = NULL;

#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
static struct ndpi_detection_module_struct *module = NULL;
static u_int32_t flow_size = 0;
static u_int32_t id_size = 0;
typedef struct {
    struct ndpi_flow_struct *flow;
    struct ndpi_id_struct *src;
    struct ndpi_id_struct *dst;
    u_int16_t protocol;
    bool done;
} ndpi_context;

static void ndpi_debug_function(u_int32_t protocol, void *module_struct,
                                ndpi_log_level_t log_level, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static bool ndpi_flow_giveup(InetFlow * flow)
{
    u_int32_t flow_protocol = inet_flow_protocol(flow);
    uint64_t packets = flow->packets;
    return ((flow_protocol != IPPROTO_UDP && flow_protocol != IPPROTO_TCP) ||
            (flow_protocol == IPPROTO_UDP && packets > 8) ||
            (flow_protocol == IPPROTO_TCP && packets > 10));
}

static void analyse_frame(InetFlow * flow, const uint8_t * iph, uint32_t length)
{
    ndpi_context *ndpi;
    ndpi = (ndpi_context *) flow->context;
    const u_int64_t time = 0;
#if defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    ndpi_protocol protocol;
#else
    u_int16_t protocol;
#endif

    if (!ndpi) {
        ndpi = ndpi_calloc(1, sizeof(ndpi_context));
        ndpi->flow = ndpi_calloc(1, flow_size);
        ndpi->src = ndpi_calloc(1, id_size);
        ndpi->dst = ndpi_calloc(1, id_size);
        flow->context = (gpointer) ndpi;
    } else if (ndpi->done) {
        return;
    }

    protocol =
        ndpi_detection_process_packet(module, ndpi->flow, iph, length, time,
                                      ndpi->src, ndpi->dst);

#if defined(LIBNDPI_NEWEST_API)
    ndpi->protocol = protocol.app_protocol;
#elif defined(LIBNDPI_NEW_API)
    ndpi->protocol = protocol.protocol;
#else
    ndpi->protocol = protocol;
#endif
    if (ndpi->protocol == 0 && ndpi_flow_giveup(flow)) {
        protocol = ndpi_detection_giveup(module, ndpi->flow, true);
#if defined(LIBNDPI_NEWEST_API)
        ndpi->protocol = protocol.app_protocol;
#elif defined(LIBNDPI_NEW_API)
        ndpi->protocol = protocol.protocol;
#else
        ndpi->protocol = protocol;
#endif
        ndpi->done = 1;
    }

    if (verbose)
        g_print("Protocol: %s(%d)\n",
                ndpi_get_proto_name(module, ndpi->protocol), ndpi->protocol);
}
#endif

static void process_frame(const uint8_t * frame, uint32_t length)
{
    const uint8_t *iph = NULL;
    InetFlow *flow =
        inet_flow_get_full(table, frame, length, 0, 0, TRUE, TRUE, TRUE, &iph, NULL);
    if (flow && iph) {
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
        if (dpi)
            analyse_frame(flow, iph, length - (iph - frame));
#endif
        frames++;
    }
    return;
}

static void process_pcap(const char *filename)
{
    char error_pcap[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    const uint8_t *frame;
    struct pcap_pkthdr hdr;

    pcap = pcap_open_offline(filename, error_pcap);
    if (pcap == NULL) {
        g_printf("Invalid pcap file: %s\n", filename);
        return;
    }

    g_printf("Reading \"%s\"\n", filename);
    while ((frame = pcap_next(pcap, &hdr)) != NULL) {
        process_frame(frame, hdr.caplen);
    }
    pcap_close(pcap);

    g_printf("\nProcessed %d frames," " %" G_GUINT64_FORMAT " misses,"
             " %" G_GUINT64_FORMAT " hits," " %" G_GUINT32_FORMAT " flows\n",
             frames, table->misses, table->hits, inet_flow_table_size(table));
}

static void print_flow(InetFlow * flow, gpointer data)
{
    struct sockaddr_in *lip, *uip;
    char lips[INET6_ADDRSTRLEN];
    char uips[INET6_ADDRSTRLEN];
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    ndpi_context *ndpi = (ndpi_context *) flow->context;
    char *proto = dpi ? ndpi_get_proto_name(module, ndpi->protocol) : "";
    if (strcmp(proto, "Unknown") == 0)
        proto = "";
#endif

    lip = (struct sockaddr_in *)inet_tuple_get_lower(&flow->tuple);
    uip = (struct sockaddr_in *)inet_tuple_get_upper(&flow->tuple);
    inet_ntop(AF_INET, &lip->sin_addr, lips, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &uip->sin_addr, uips, INET_ADDRSTRLEN);
    g_printf("0x%04x: %-16s %-16s %-2d %-5d %-5d  %-5zu %s %s\n",
             flow->hash, lips, uips, inet_flow_protocol(flow), lip->sin_port, uip->sin_port,
             flow->packets,
             flow->state == FLOW_NEW ? "NEW   " : (flow->state ==
                                                   FLOW_OPEN ? "OPEN  " : "CLOSED"),
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
             dpi ? proto :
#endif
             "");
}

static void clean_flow(InetFlow * flow, gpointer data)
{
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    ndpi_context *ndpi = (ndpi_context *) flow->context;
    if (ndpi) {
        ndpi_free_flow(ndpi->flow);
        ndpi_free(ndpi->src);
        ndpi_free(ndpi->dst);
        free(ndpi);
    }
#endif
    inet_flow_unref(flow);
}

static GOptionEntry entries[] = {
    { "pcap", 'p', 0, G_OPTION_ARG_STRING, &filename, "Pcap file to use", NULL },
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    { "dpi", 'd', 0, G_OPTION_ARG_NONE, &dpi, "Analyse frames using DPI", NULL },
#endif
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
    { NULL }
};

int main(int argc, char **argv)
{
    GError *error = NULL;
    GOptionContext *context;
    gint i, j;

    /* Parse options */
    context = g_option_context_new("- Demonstration of libinetflow");
    g_option_context_add_main_entries(context, entries, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_print("%s", g_option_context_get_help(context, FALSE, NULL));
        g_print("ERROR: %s\n", error->message);
        exit(1);
    }
    if (filename == NULL) {
        g_print("%s", g_option_context_get_help(context, FALSE, NULL));
        g_print("ERROR: Require pcap file\n");
        exit(1);
    }
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    if (dpi) {
        NDPI_PROTOCOL_BITMASK all;
        flow_size = ndpi_detection_get_sizeof_ndpi_flow_struct();
        id_size = ndpi_detection_get_sizeof_ndpi_id_struct();
#if defined(LIBNDPI_NEWEST_API)
        module = ndpi_init_detection_module();
#else
        module = ndpi_init_detection_module(1000, malloc, free, ndpi_debug_function);
#endif
        NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(module, &all);
    }
#endif

    table = inet_flow_table_new();
    process_pcap(filename);
    g_printf
        ("Hash    lip              uip            prot lport uport  pkts  state  app\n");
    inet_flow_foreach(table, (IFFunc) print_flow, NULL);
    inet_flow_foreach(table, (IFFunc) clean_flow, NULL);
    inet_flow_table_unref(table);
#if defined(LIBNDPI_NEWEST_API)
    if (module)
        ndpi_exit_detection_module(module);
#elif defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API)
    if (module)
        ndpi_exit_detection_module(module, free);
#endif
    g_option_context_free(context);
    return 0;
}
