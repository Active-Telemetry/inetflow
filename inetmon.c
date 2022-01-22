/* inetmon- IP Network Monitor
 *
 * Copyright (C) 2021 ECLB Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <glib.h>
#include <glib/gprintf.h>
#include <signal.h>
#include <pcap.h>
#include <curses.h>

static gchar *iface = NULL;
static gchar *filename = NULL;
static gchar *private = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
static int interval = 1;
static gboolean running = TRUE;

/* Counters */
static gint frames = 0;
static gint arp = 0;
static gint ipv4 = 0;
static gint ipv6 = 0;
static gint unknown = 0;

#define ETH_PROTOCOL_ARP        0x0806
#define ETH_PROTOCOL_IP         0x0800
#define ETH_PROTOCOL_IPV6       0x86DD

typedef struct ethernet_hdr_t {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t protocol;
} __attribute__ ((packed)) ethernet_hdr_t;

typedef struct ip_hdr_t {
    uint8_t ihl_version;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__ ((packed)) ip_hdr_t;

#define MAXIMUM_SNAPLEN 262144

static inline uint64_t
get_time_us (void)
{
    struct timeval tv;
    gettimeofday (&tv, NULL);
    return (tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec);
}

typedef struct subnet {
    unsigned short  family;
    unsigned short  prefix;
    struct sockaddr_storage sa;
} subnet;

static GList *private_subnets = NULL;

static bool
is_local_v4(void)
{
    // unsigned int mask = 0xFFFFFFFF << (32 - network_bits);
}

static void process_frame(const uint8_t * frame, uint32_t length)
{
    ethernet_hdr_t *eth = (ethernet_hdr_t *)frame;

    frames++;
    switch (ntohs(eth->protocol))
    {
    case ETH_PROTOCOL_ARP:
        arp++;
        break;
    case ETH_PROTOCOL_IP:
        ipv4++;
        break;
    case ETH_PROTOCOL_IPV6:
        ipv6++;
        break;
    default:
        unknown++;
        break;
    }
}

static void dump_state(void)
{
    g_printf("\r\n%8d frames (ARP:%d IPv4:%d IPv6:%d Unknown:%d)\r\n", frames, arp, ipv4, ipv6, unknown);
}

static void process_interface(const char *interface, int snaplen, int promisc, int to_ms)
{
    char error_pcap[PCAP_ERRBUF_SIZE] = { 0 };
    struct pcap_pkthdr hdr;
    const uint8_t *frame;
    pcap_t *pcap;
    int status;
    uint64_t lasttime;
    int col, row;

    pcap = pcap_open_live(interface, snaplen, promisc, to_ms, error_pcap);
    if (pcap == NULL) {
        g_printf("%s: Failed to open interface: %s\r\n", interface, error_pcap);
        return;
    }

    g_printf("Reading from \"%s\"\r\n", interface);
    lasttime = get_time_us();
    initscr();
    getmaxyx(stdscr, row, col);
    while (running && (frame = pcap_next(pcap, &hdr)) != NULL) {
        process_frame(frame, hdr.caplen);
        if (interval && ((get_time_us() - lasttime) / 1000000) > interval)
        {
            lasttime = get_time_us();
            clear();
            refresh();
            dump_state();
        }
    }
    endwin();
    dump_state();
    pcap_close(pcap);
}

static void process_pcap(const char *filename)
{
    char error_pcap[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;
    const uint8_t *frame;
    struct pcap_pkthdr hdr;

    pcap = pcap_open_offline(filename, error_pcap);
    if (pcap == NULL) {
        g_printf("Invalid pcap file: %s\r\n", filename);
        return;
    }
    g_printf("Reading \"%s\"\r\n", filename);
    while (running && (frame = pcap_next(pcap, &hdr)) != NULL) {
        process_frame(frame, hdr.caplen);
    }
    dump_state();
    pcap_close(pcap);
}

void
parse_private_networks(const gchar *private)
{
    char *ptr, *parameter, *subnets;

    subnets = g_strdup (private);
    parameter = strtok_r (subnets, ",", &ptr);
    while (parameter)
    {
        subnet *sn = g_malloc0(sizeof(subnet));
        char *slash = strchr(parameter, '/');

        if (!slash)
            g_error("Invalid subnet \"%s\"\n", parameter);
        *slash = '\0';
        slash++;
        sn->prefix = atoi(slash);

        if (inet_pton(AF_INET, parameter, &((struct sockaddr_in *)&sn->sa)->sin_addr) == 1)
        {
            sn->family = AF_INET;
            if (sn->prefix < 8 || sn->prefix > 32)
                g_error("Invalid IP mask \"%s\"\n", slash);
        }
        else if (inet_pton(AF_INET6, parameter, &((struct sockaddr_in6 *)&sn->sa)->sin6_addr) == 1)
        {
            sn->family = AF_INET6;
            if (sn->prefix < 8 || sn->prefix > 128)
                g_error("Invalid IPv6 mask \"%s\"\n", slash);
        }
        else
            g_error("Invalid IP address \"%s\"\n", parameter);

        private_subnets = g_list_append(private_subnets, (gpointer)sn);
        parameter = strtok_r(NULL, ",", &ptr);

        char str[INET6_ADDRSTRLEN];
        if (sn->family == AF_INET)
            inet_ntop(sn->family, &((struct sockaddr_in *)&sn->sa)->sin_addr, str, INET_ADDRSTRLEN);
        else
            inet_ntop(sn->family, &((struct sockaddr_in6 *)&sn->sa)->sin6_addr, str, INET_ADDRSTRLEN);
        printf("Adding private %s subnet %s/%d\n", sn->family == AF_INET ? "IPv4" : "IPv6", str, sn->prefix);
    }
    g_free(subnets);
}

static GOptionEntry entries[] = {
    { "filename", 'f', 0, G_OPTION_ARG_STRING, &filename, "Pcap file to use", NULL },
    { "interface", 'i', 0, G_OPTION_ARG_STRING, &iface, "Interface to capture on", NULL },
    { "timeout", 't', 0, G_OPTION_ARG_INT, &interval, "Display timeout", NULL },
    { "private", 'p', 0, G_OPTION_ARG_STRING, &private, "Private Subnets (defaults to \"10.0.0.0/8,172.16.0.0/12,192.168.0.0/16\")", NULL },
    { NULL }
};

static void intHandler(int dummy)
{
    running = FALSE;
}

int main(int argc, char **argv)
{
    GError *error = NULL;
    GOptionContext *context;
    gint i, j;

    /* Parse options */
    context = g_option_context_new("- IP Network Monitor");
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
    parse_private_networks(private);

    signal(SIGINT, intHandler);
    if (filename)
        process_pcap(filename);
    else
        process_interface(iface, MAXIMUM_SNAPLEN, 1, 1000);

    g_option_context_free(context);
    return 0;
}
