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
#include <signal.h>
#include <curses.h>
#include "inetflow.h"

static gboolean dpi = FALSE;
static gchar *filename = NULL;
static gchar *iface = NULL;
static int interval = 1;
static gboolean verbose = FALSE;
static gint frames = 0;
static InetFlowTable *table = NULL;
static gboolean running = true;

#define MAXIMUM_SNAPLEN 262144

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

static void print_flow(InetFlow * flow, gpointer data);

static inline uint64_t
get_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

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

static gint compare_flow (InetFlow *a, InetFlow *b)
{
    return (b->inbytes + b->outbytes) - (a->inbytes + a->outbytes);
}

static void collect_flow(InetFlow * flow, gpointer data)
{
    GList **list = (GList **)data;
    *list = g_list_insert_sorted(*list, (gpointer)flow, (GCompareFunc) compare_flow);
}

static void dump_stats(void)
{
    int count = 0;
    int col, row;
    GList *flows = NULL;

    getmaxyx(stdscr, row, col);
    clear();
    refresh();
    inet_flow_foreach(table, (IFFunc) collect_flow, &flows);
    count = 0;
    g_printf("Hash    lip                                           uip                                         prot lport uport  pkts  inbytes outbytes state  app\r\n");
    for (GList *iter = flows; iter && (count < (row-2)); iter = g_list_next(iter))
    {
        InetFlow *flow = (InetFlow *)iter->data;
        if ((flow->inbytes + flow->outbytes) < 1000)
            continue;
        print_flow(flow, NULL);
        count++;
    }
    g_list_free (flows);
}

static void process_interface(const char *interface, int snaplen, int promisc, int to_ms)
{
    char error_pcap[PCAP_ERRBUF_SIZE] = { 0 };
    struct pcap_pkthdr hdr;
    const uint8_t *frame;
    pcap_t *pcap;
    int status;
    uint64_t lasttime = get_time_us();

    pcap = pcap_open_live(interface, snaplen, promisc, to_ms, error_pcap);
    if (pcap == NULL) {
        g_printf("%s: Failed to open interface: %s\n", interface, error_pcap);
        return;
    }

    g_printf("Reading from \"%s\"\n", interface);
    initscr();
    while (running && (frame = pcap_next(pcap, &hdr)) != NULL) {
        process_frame(frame, hdr.caplen);
        if (interval && ((get_time_us() - lasttime) / 1000000) > interval)
        {
            lasttime = get_time_us();
            inet_flow_expire (table, lasttime);
            dump_stats();
        }
    }
    endwin();
    pcap_close(pcap);

    g_printf("\nProcessed %d frames," " %" G_GUINT64_FORMAT " misses,"
             " %" G_GUINT64_FORMAT " hits," " %" G_GUINT32_FORMAT " flows\n",
             frames, table->misses, table->hits, inet_flow_table_size(table));
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
    while (running && (frame = pcap_next(pcap, &hdr)) != NULL) {
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
    inet_ntop(inet_tuple_family(&flow->tuple), &lip->sin_addr, lips, INET6_ADDRSTRLEN);
    inet_ntop(inet_tuple_family(&flow->tuple), &uip->sin_addr, uips, INET6_ADDRSTRLEN);
    g_printf("0x%04x: %-45s %-45s %-2d %-5d %-5d  %-5zu %-7zu %-7zu  %s %s\r\n",
             flow->hash, uips, lips, inet_flow_protocol(flow), uip->sin_port, lip->sin_port,
             flow->packets, flow->inbytes, flow->outbytes,
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
    { "interface", 'i', 0, G_OPTION_ARG_STRING, &iface, "Interface to capture on", NULL },
#if defined(LIBNDPI_OLD_API) || defined(LIBNDPI_NEW_API) || defined(LIBNDPI_NEWEST_API)
    { "dpi", 'd', 0, G_OPTION_ARG_NONE, &dpi, "Analyse frames using DPI", NULL },
#endif
    { "timeout", 't', 0, G_OPTION_ARG_INT, &interval, "Display timeout", NULL },
    { "verbose", 'v', 0, G_OPTION_ARG_NONE, &verbose, "Be verbose", NULL },
    { NULL }
};

static void intHandler(int dummy)
{
    running = false;
}

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
    if ((!filename && !iface) || filename && iface) {
        g_print("%s", g_option_context_get_help(context, FALSE, NULL));
        g_print("ERROR: Require interface or pcap file\n");
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

    signal(SIGINT, intHandler);
    table = inet_flow_table_new();
    if (filename)
        process_pcap(filename);
    else
        process_interface(iface, MAXIMUM_SNAPLEN, 1, 1000);
    g_printf("Hash    lip                                           uip                                         prot lport uport  pkts  inbytes outbytes state  app\r\n");
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
