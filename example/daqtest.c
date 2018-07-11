/*
** Copyright (C) 2014-2018 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2010-2013 Sourcefire, Inc.
** Author: Michael R. Altizer <mialtize@cisco.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <daq.h>
#include <daq_dlt.h>

typedef enum
{
    PING_ACTION_PASS = 0,
    PING_ACTION_DROP,
    PING_ACTION_SPOOF,
    PING_ACTION_REPLACE,
    PING_ACTION_BLACKLIST,
    PING_ACTION_WHITELIST,
    PING_ACTION_CLONE,
    MAX_PING_ACTION = PING_ACTION_CLONE
} PingAction;

typedef struct _IPv4Addr
{
    struct _IPv4Addr *next;
    struct in_addr addr;
} IPv4Addr;

typedef struct _DAQTestModuleConfig
{
    struct _DAQTestModuleConfig *next;
    char *module_name;
    char **variables;
    unsigned int num_variables;
    DAQ_Mode mode;
} DAQTestModuleConfig;

typedef struct _DAQTestConfig
{
    int verbosity;
    const char **module_paths;
    unsigned int num_module_paths;
    DAQTestModuleConfig *module_configs;
    char *input;
    unsigned timeout;
    int snaplen;
    char *filter;
    unsigned long packet_limit;
    unsigned long timeout_limit;
    unsigned long delay;
    DAQ_Verdict default_verdict;
    PingAction ping_action;
    IPv4Addr *ip_addrs;
    unsigned thread_count;
    bool list_and_exit;
    bool modify_opaque_value;
    bool performance_mode;
    bool dump_packets;
} DAQTestConfig;

typedef struct _DAQTestThreadContext
{
    const DAQTestConfig *cfg;
    DAQ_Instance_h instance;
    pthread_t tid;
    unsigned long packet_count;
    void *newconfig;
    void *oldconfig;
    volatile bool done;
    volatile bool exited;
} DAQTestThreadContext;

typedef struct _DAQTestPacket
{
    DAQ_Msg_h msg;
    const DAQTestThreadContext *ctxt;
    const DAQ_PktHdr_t *hdr;
    const uint8_t *packet;
    const struct ether_header *eth;
    const struct arphdr *arp;
    const struct iphdr *ip;
    const struct ip6_hdr *ip6;
    const struct icmphdr *icmp;
    const struct icmp6_hdr *icmp6;
    const struct tcphdr *tcp;
    const struct udphdr *udp;
    uint16_t vlan_tags;
} DAQTestPacket;

#define VTH_PRIORITY(vh)  ((ntohs((vh)->vth_pri_cfi_vlan) & 0xe000) >> 13)
#define VTH_CFI(vh)       ((ntohs((vh)->vth_pri_cfi_vlan) & 0x0100) >> 12)
#define VTH_VLAN(vh)      ((unsigned short)(ntohs((vh)->vth_pri_cfi_vlan) & 0x0FFF))

typedef struct _VlanTagHdr
{
    uint16_t vth_pri_cfi_vlan;
    uint16_t vth_proto;  /* protocol field... */
} VlanTagHdr;


#ifdef USE_STATIC_MODULES
extern DAQ_Module_h static_modules[];
#endif

static uint8_t normal_ping_data[IP_MAXPACKET];
static uint8_t fake_ping_data[IP_MAXPACKET];
static uint8_t local_mac_addr[ETH_ALEN];

static volatile sig_atomic_t pending_signal = 0;
static int dlt;

const char *ping_action_strings[MAX_PING_ACTION+1] =
{
    "Pass", "Block", "Spoof", "Replace", "Blacklist", "Whitelist", "Clone"
};


static void handler(int sig)
{
    pending_signal = sig;
}

static void usage(void)
{
    printf("Usage: daqtest -d <daq_module> -i <input> [OPTION]...\n");
    printf("  -A <ip>           Specify an IP to respond to ARPs on (may be specified multiple times)\n");
    printf("  -c <num>          Maximum number of packets to acquire (default = 0, <= 0 is unlimited)\n");
    printf("  -C <key[=value]>  Set a DAQ configuration variable key/value pair\n");
    printf("  -D <delay>        Specify a millisecond delay to be added to each packet processed\n");
    printf("  -f <bpf>          Specify the Berkley Packet Filter string to use for filtering\n");
    printf("  -h                Display this usage text and exit\n");
    printf("  -l                Print a list of modules found and exit\n");
    printf("  -m <path>         Specify a direcotyr path to search for modules (may be specified multiple times)\n");
    printf("  -M <mode>         Specify the mode (passive (default), inline, read-file)\n");
    printf("  -O                Enable modifying the flow's opaque value on each packet\n");
    printf("  -p                Enable performance testing mode - auto-PASS and no decoding\n");
    printf("  -P <action>       Specify the action to perform when a ping is received (none (default), block, spoof, replace, blacklist, whitelist, clone)\n");
    printf("  -s <len>          Specify the capture length in bytes (default = 1518)\n");
    printf("  -t <num>          Specify the receive timeout in milliseconds (default = 0, 0 is unlimited)\n");
    printf("  -T <num>          Maximum number of receive timeouts to encounter before exiting (default = 0, 0 is unlimited)\n");
    printf("  -v                Increase the verbosity level of the DAQ library (may be specified multiple times)\n");
    printf("  -V <verdict>      Specify a default verdict to render on packets (pass (default), block, blacklist, whitelist)\n");
    printf("  -x                Print a hexdump of each packet received\n");
    printf("  -z <num>          Specify the number of packet threads to run (default = 1)\n");
}

static void print_mac(const uint8_t *addr)
{
    printf("%.2hx:%.2hx:%.2hx:%.2hx:%.2hx:%.2hx", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static void print_hex_dump(const uint8_t *data, unsigned int len)
{
    unsigned int i;

    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0)
            printf("\n");
        else if (i % 2 == 0)
            printf(" ");
        printf("%02x", data[i]);
    }
    printf("\n\n");
}

/*
 * Checksum routine for Internet Protocol family headers (C version) (from ping.c)
 */
static uint16_t in_cksum(uint16_t *addr, int len)
{
    int nleft = len;
    uint16_t *w = addr;
    uint32_t sum = 0;
    uint16_t answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
    {
        answer = 0;
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */

    //printf("Checksummed with length of %d, answer was %hu\n", len, answer);
    return (answer);
}

static void initialize_static_data(void)
{
    char c;
    unsigned i;

    for (c = 0, i = 0; i < IP_MAXPACKET; c++, i++)
    {
        normal_ping_data[i] = c;
        fake_ping_data[i] = 'A';
    }

    srand(time(NULL) + getpid());   /* seed the RNG */
    for (i = 0; i < sizeof(local_mac_addr); i++)
        local_mac_addr[i] = (uint8_t) rand();
    local_mac_addr[0] &= 0xfe;    /* clear multicast bit */
    local_mac_addr[0] |= 0x02;    /* set local assignment bit (IEEE802) */
}

static int replace_icmp_data(DAQTestPacket *dtp)
{
    struct icmphdr *icmp;
    uint8_t *data;
    size_t dlen;
    int offset;
    int modified = 0;

    icmp = (struct icmphdr *) dtp->icmp;
    icmp->checksum = 0;

    dlen = ntohs(dtp->ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    data = (uint8_t *) icmp + sizeof(struct icmphdr);
    offset = 0;
    if (dlen > sizeof(sizeof(struct timeval)))
    {
        printf("Accounting for ping timing data (%zu bytes).\n", sizeof(struct timeval));
        offset = sizeof(struct timeval);
        data += offset;
        dlen -= offset;
    }
/*
    printf("%d bytes of data:\n", dlen);
    print_hex_dump(data, dlen);
*/
    if (memcmp(data, normal_ping_data + offset, dlen) == 0)
    {
        printf("Replacing the ping request padding.\n");
        memcpy(data, fake_ping_data + offset, dlen);
        modified = 1;
    }
    else if (memcmp(data, fake_ping_data + offset, dlen) == 0)
    {
        printf("Replacing the ping reply padding.\n");
        memcpy(data, normal_ping_data + offset, dlen);
        modified = 1;
    }

    if (modified)
    {
        icmp->checksum = 0;
        icmp->checksum = in_cksum((uint16_t *) icmp, ntohs(dtp->ip->tot_len) - sizeof(struct iphdr));
    }

    return modified;
}

static uint8_t *forge_etharp_reply(DAQTestPacket *dtp, const uint8_t *mac_addr)
{
    const uint8_t *request = dtp->packet;
    uint8_t *reply;
    const struct ether_header *eth_request;
    struct ether_header *eth_reply;
    const struct ether_arp *etharp_request;
    struct ether_arp *etharp_reply;
    size_t arphdr_offset;

    arphdr_offset = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr);
    reply = calloc(arphdr_offset + sizeof(struct ether_arp), sizeof(uint8_t));

    /* Set up the ethernet header... */
    eth_request = dtp->eth;
    eth_reply = (struct ether_header *) reply;
    memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETH_ALEN);
    memcpy(eth_reply->ether_shost, mac_addr, ETH_ALEN);
    memcpy(reply + ETH_ALEN * 2, request + ETH_ALEN * 2, arphdr_offset - ETH_ALEN * 2);

    /* Now the ARP header... */
    etharp_request = (const struct ether_arp *) dtp->arp;
    etharp_reply = (struct ether_arp *) (reply + arphdr_offset);
    memcpy(&etharp_reply->ea_hdr, &etharp_request->ea_hdr, sizeof(struct arphdr));
    etharp_reply->ea_hdr.ar_op = htons(ARPOP_REPLY);

    /* Finally, the ethernet ARP reply... */
    memcpy(etharp_reply->arp_sha, mac_addr, ETH_ALEN);
    memcpy(etharp_reply->arp_spa, etharp_request->arp_tpa, 4);
    memcpy(etharp_reply->arp_tha, etharp_request->arp_sha, ETH_ALEN);
    memcpy(etharp_reply->arp_tpa, etharp_request->arp_spa, 4);

    return reply;
}

static uint8_t *forge_icmp_reply(DAQTestPacket *dtp)
{
    const uint8_t *request = dtp->packet;
    uint8_t *reply;
    const struct ether_header *eth_request;
    struct ether_header *eth_reply;
    const struct iphdr *ip_request;
    struct iphdr *ip_reply;
    const struct icmphdr *icmp_request;
    struct icmphdr *icmp_reply;
    uint32_t dlen;
    size_t arphdr_offset;

    arphdr_offset = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr);
    reply = calloc(arphdr_offset + dtp->ip->tot_len, sizeof(uint8_t));

    /* Set up the ethernet header... */
    eth_request = dtp->eth;
    eth_reply = (struct ether_header *) reply;
    memcpy(eth_reply->ether_dhost, eth_request->ether_shost, ETH_ALEN);
    memcpy(eth_reply->ether_shost, eth_request->ether_dhost, ETH_ALEN);
    memcpy(reply + ETH_ALEN * 2, request + ETH_ALEN * 2, arphdr_offset - ETH_ALEN * 2);

    /* Now the IP header... */
    ip_request = dtp->ip;
    ip_reply = (struct iphdr *) (reply + arphdr_offset);
    ip_reply->ihl = ip_request->ihl;
    ip_reply->version = ip_request->version;
    ip_reply->tos = ip_request->tos;
    ip_reply->tot_len = ip_request->tot_len;
    ip_reply->id = ip_request->id;
    ip_reply->frag_off = ip_request->frag_off;
    ip_reply->ttl = ip_request->ttl;
    ip_reply->protocol = ip_request->protocol;
    ip_reply->check = 0;
    ip_reply->saddr = ip_request->daddr;
    ip_reply->daddr = ip_request->saddr;
    ip_reply->check = in_cksum((uint16_t *) ip_reply, ip_reply->ihl * 4);

    /* And the ICMP header... */
    icmp_request = dtp->icmp;
    icmp_reply = (struct icmphdr *) (reply + arphdr_offset + sizeof(struct iphdr));
    icmp_reply->type = ICMP_ECHOREPLY;
    icmp_reply->code = 0;
    icmp_reply->checksum = 0;
    icmp_reply->un.echo.id = icmp_request->un.echo.id;
    icmp_reply->un.echo.sequence = icmp_request->un.echo.sequence;

    /* Copy the ICMP padding... */
    dlen = ntohs(ip_request->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    memcpy(icmp_reply + 1, icmp_request + 1, dlen);

    /* Last, but not least, checksum the ICMP packet */
    icmp_reply->checksum = in_cksum((uint16_t *) icmp_reply, ntohs(ip_request->tot_len) - sizeof(struct iphdr));

    return reply;
}

static DAQ_Verdict process_ping(DAQTestPacket *dtp)
{
    int rc;

    switch (dtp->ctxt->cfg->ping_action)
    {
        case PING_ACTION_PASS:
            break;

        case PING_ACTION_SPOOF:
            if (dtp->icmp->type == ICMP_ECHO && dtp->eth)
            {
                uint8_t *reply;
                size_t reply_len;

                reply = forge_icmp_reply(dtp);
                reply_len = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr) + ntohs(dtp->ip->tot_len);
                printf("Injecting forged ICMP reply back to source! (%zu bytes)\n", reply_len);
                rc = daq_instance_inject(dtp->ctxt->instance, dtp->msg, reply, reply_len, 1);
                if (rc == DAQ_ERROR_NOTSUP)
                    printf("This module does not support packet injection.\n");
                else if (rc != DAQ_SUCCESS)
                    printf("Failed to inject ICMP reply: %s\n", daq_instance_get_error(dtp->ctxt->instance));
                free(reply);
                return DAQ_VERDICT_BLOCK;
            }
            break;

        case PING_ACTION_DROP:
            printf("Blocking the ping packet.\n");
            return DAQ_VERDICT_BLOCK;

        case PING_ACTION_REPLACE:
            if (dtp->icmp)
            {
                replace_icmp_data(dtp);
                return DAQ_VERDICT_REPLACE;
            }
            break;

        case PING_ACTION_BLACKLIST:
            printf("Blacklisting the ping's flow.\n");
            return DAQ_VERDICT_BLACKLIST;

        case PING_ACTION_WHITELIST:
            printf("Whitelisting the ping's flow.\n");
            return DAQ_VERDICT_WHITELIST;

        case PING_ACTION_CLONE:
            if (dtp->eth)
            {
                printf("Injecting cloned ICMP packet.\n");
                rc = daq_instance_inject(dtp->ctxt->instance, dtp->msg, dtp->packet, daq_msg_get_data_len(dtp->msg), 0);
                if (rc == DAQ_ERROR_NOTSUP)
                    printf("This module does not support packet injection.\n");
                else if (rc != DAQ_SUCCESS)
                    printf("Failed to inject cloned ICMP packet: %s\n", daq_instance_get_error(dtp->ctxt->instance));
                printf("Blocking the original ICMP packet.\n");
                return DAQ_VERDICT_BLOCK;
            }
            break;
    }
    return DAQ_VERDICT_PASS;
}

static DAQ_Verdict process_icmp(DAQTestPacket *dtp)
{
    unsigned int dlen;

    dlen = ntohs(dtp->ip->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr);
    printf("  ICMP: Type %hu  Code %hu  Checksum %hu  (%u bytes of data)\n",
           dtp->icmp->type, dtp->icmp->code, dtp->icmp->checksum, dlen);
    if (dtp->icmp->type == ICMP_ECHO || dtp->icmp->type == ICMP_ECHOREPLY)
    {
        printf("   Echo: ID %hu  Sequence %hu\n",
               ntohs(dtp->icmp->un.echo.id), ntohs(dtp->icmp->un.echo.sequence));
        return process_ping(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_icmp6(DAQTestPacket *dtp)
{
    unsigned int dlen;

    dlen = ntohs(dtp->ip6->ip6_plen) - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
    printf("  ICMP: Type %hu  Code %hu  Checksum %hu  (%u bytes of data)\n",
           dtp->icmp6->icmp6_type, dtp->icmp6->icmp6_code, dtp->icmp6->icmp6_cksum, dlen);
    if (dtp->icmp6->icmp6_type == ICMP6_ECHO_REQUEST || dtp->icmp6->icmp6_type == ICMP6_ECHO_REPLY)
    {
        printf("   Echo: ID %hu  Sequence %hu\n",
               ntohs(dtp->icmp6->icmp6_id), ntohs(dtp->icmp6->icmp6_seq));
        //return process_ping(dtp);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_arp(DAQTestPacket *dtp)
{
    const struct ether_arp *etharp;
    struct in_addr addr;
    IPv4Addr *ip;
    uint8_t *reply;
    size_t reply_len;

    printf(" ARP: Hardware Type %hu (%hu)  Protocol Type %.4hX (%hu)  Operation %hu\n",
            ntohs(dtp->arp->ar_hrd), dtp->arp->ar_hln, ntohs(dtp->arp->ar_pro),
            dtp->arp->ar_pln, ntohs(dtp->arp->ar_op));

    if (ntohs(dtp->arp->ar_hrd) != ARPHRD_ETHER)
        return dtp->ctxt->cfg->default_verdict;

    etharp = (const struct ether_arp *) dtp->arp;

    printf("  Sender: ");
    print_mac(etharp->arp_sha);
    memcpy(&addr.s_addr, etharp->arp_spa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    printf("  Target: ");
    print_mac(etharp->arp_tha);
    memcpy(&addr.s_addr, etharp->arp_tpa, 4);
    printf(" (%s)\n", inet_ntoa(addr));

    if (ntohs(dtp->arp->ar_op) != ARPOP_REQUEST || ntohs(dtp->arp->ar_pro) != ETH_P_IP)
        return dtp->ctxt->cfg->default_verdict;

    for (ip = dtp->ctxt->cfg->ip_addrs; ip; ip = ip->next)
    {
        if (!memcmp(&addr, &ip->addr, sizeof(addr)))
            break;
    }

    /* Only perform Ethernet ARP spoofing when in ping spoofing mode and passive mode. */
    //if (!ip && (dtp->ctxt->cfg->ping_action != PING_ACTION_SPOOF || dtp->ctxt->cfg->mode != DAQ_MODE_PASSIVE))
    if (!ip || dtp->ctxt->cfg->ping_action != PING_ACTION_SPOOF)
       return dtp->ctxt->cfg->default_verdict;

    reply = forge_etharp_reply(dtp, local_mac_addr);
    reply_len = sizeof(*dtp->eth) + dtp->vlan_tags * sizeof(VlanTagHdr) + sizeof(struct ether_arp);
    printf("Injecting forged Ethernet ARP reply back to source (%zu bytes)!\n", reply_len);
    if (daq_instance_inject(dtp->ctxt->instance, dtp->msg, reply, reply_len, 1))
        printf("Failed to inject ARP reply: %s\n", daq_instance_get_error(dtp->ctxt->instance));
    free(reply);

    return DAQ_VERDICT_BLOCK;
}

static DAQ_Verdict process_ip6(DAQTestPacket *dtp)
{
    char src_addr_str[INET6_ADDRSTRLEN], dst_addr_str[INET6_ADDRSTRLEN];

    /* Print source and destination IP addresses. */
    inet_ntop(AF_INET6, &dtp->ip6->ip6_src, src_addr_str, sizeof(src_addr_str));
    inet_ntop(AF_INET6, &dtp->ip6->ip6_dst, dst_addr_str, sizeof(dst_addr_str));
    printf(" IP6: %s -> %s\n", src_addr_str, dst_addr_str);

    uint8_t next_hdr = dtp->ip6->ip6_nxt;
    if (next_hdr == IPPROTO_FRAGMENT)
    {
        const struct ip6_frag *frag = (const struct ip6_frag *) (dtp->ip6 + 1);
        next_hdr = frag->ip6f_nxt;
    }

    switch (next_hdr)
    {
        case IPPROTO_TCP:
            printf(" Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf(" Protocol: UDP\n");
            break;
        case IPPROTO_ICMPV6:
            printf(" Protocol: ICMPv6\n");
            return process_icmp6(dtp);
        default:
            printf(" Protocol: unknown\n");
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_ip(DAQTestPacket *dtp)
{
    struct in_addr addr;
    char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];

    /* Print source and destination IP addresses. */
    addr.s_addr = dtp->ip->saddr;
    inet_ntop(AF_INET, &addr, src_addr_str, sizeof(src_addr_str));
    addr.s_addr = dtp->ip->daddr;
    inet_ntop(AF_INET, &addr, dst_addr_str, sizeof(dst_addr_str));
    printf(" IP: %s -> %s (%hu bytes) (checksum: %hu) (type: 0x%X)\n",
            src_addr_str, dst_addr_str, ntohs(dtp->ip->tot_len), dtp->ip->check, ntohs(dtp->ip->protocol));

    switch (dtp->ip->protocol)
    {
        case IPPROTO_TCP:
            printf(" Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf(" Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf(" Protocol: ICMP\n");
            return process_icmp(dtp);
        case IPPROTO_IP:
            printf(" Protocol: IP\n");
            break;
        default:
            printf(" Protocol: unknown\n");
    }

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_eth(DAQTestPacket *dtp)
{
    printf("MAC: ");
    print_mac(dtp->eth->ether_shost);
    printf(" -> ");
    print_mac(dtp->eth->ether_dhost);
    printf(" (%.4hX) (%u bytes)\n", ntohs(dtp->eth->ether_type), daq_msg_get_data_len(dtp->msg));
    if (dtp->vlan_tags > 0)
    {
        uint16_t ether_type;
        uint16_t offset;

        printf(" VLAN Tags (%hu):", dtp->vlan_tags);
        ether_type = ntohs(dtp->eth->ether_type);
        offset = sizeof(*dtp->eth);
        while (ether_type == ETH_P_8021Q)
        {
            const VlanTagHdr *vlan;

            vlan = (const VlanTagHdr *) (dtp->packet + offset);
            ether_type = ntohs(vlan->vth_proto);
            offset += sizeof(*vlan);
            printf(" %hu/%hu", VTH_VLAN(vlan), VTH_PRIORITY(vlan));
        }
        printf("\n");
    }
    if (dtp->arp)
        return process_arp(dtp);

    if (dtp->ip)
        return process_ip(dtp);

    if (dtp->ip6)
        return process_ip6(dtp);

    return dtp->ctxt->cfg->default_verdict;
}

static DAQ_Verdict process_packet(DAQTestPacket *dtp)
{
    switch (dlt)
    {
        case DLT_EN10MB:
            if (dtp->eth)
                return process_eth(dtp);
            break;

        case DLT_RAW:
            if (dtp->ip)
                return process_ip(dtp);
            if (dtp->ip6)
                return process_ip6(dtp);
            break;

        default:
            printf("Unhandled datalink type: %d!\n", dlt);
    }

    return dtp->ctxt->cfg->default_verdict;
}

static void decode_icmp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->icmp = (const struct icmphdr *) cursor;
}

static void decode_icmp6(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->icmp6 = (const struct icmp6_hdr *) cursor;
}

static void decode_tcp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->tcp = (const struct tcphdr *) cursor;
}

static void decode_udp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->udp = (const struct udphdr *) cursor;
}

static void decode_ip6(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t offset;

    dtp->ip6 = (const struct ip6_hdr *) cursor;
    offset = sizeof(*dtp->ip6);

    uint8_t next_hdr = dtp->ip6->ip6_nxt;
    if (next_hdr == IPPROTO_FRAGMENT)
    {
        const struct ip6_frag *frag = (const struct ip6_frag *) (cursor + offset);
        next_hdr = frag->ip6f_nxt;
        offset += sizeof(struct ip6_frag);
    }

    switch (next_hdr)
    {
        case IPPROTO_TCP:
            decode_tcp(dtp, cursor + offset);
            break;
        case IPPROTO_UDP:
            decode_udp(dtp, cursor + offset);
            break;
        case IPPROTO_ICMPV6:
            decode_icmp6(dtp, cursor + offset);
            break;
        default:
            printf("Unknown next header: 0x%x\n", dtp->ip6->ip6_nxt);
            break;
    }
}

static void decode_ip(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t offset;

    dtp->ip = (const struct iphdr *) cursor;
    if ((dtp->ip->ihl * 4) < 20)
    {
        printf("   * Invalid IP header length: %d bytes\n", dtp->ip->ihl * 4);
        return;
    }

    offset = sizeof(*dtp->ip);

    switch (dtp->ip->protocol)
    {
        case IPPROTO_TCP:
            decode_tcp(dtp, cursor + offset);
            break;
        case IPPROTO_UDP:
            decode_udp(dtp, cursor + offset);
            break;
        case IPPROTO_ICMP:
            decode_icmp(dtp, cursor + offset);
            break;
    }
}

static void decode_arp(DAQTestPacket *dtp, const uint8_t *cursor)
{
    dtp->arp = (const struct arphdr *) cursor;
}

static void decode_eth(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint16_t ether_type;
    uint16_t offset;

    dtp->eth = (const struct ether_header *) (cursor);
    ether_type = ntohs(dtp->eth->ether_type);
    offset = sizeof(*dtp->eth);
    while (ether_type == ETH_P_8021Q)
    {
        const VlanTagHdr *vlan;

        vlan = (const VlanTagHdr *) (cursor + offset);
        ether_type = ntohs(vlan->vth_proto);
        offset += sizeof(*vlan);
        dtp->vlan_tags++;
    }
    if (ether_type == ETH_P_ARP)
        decode_arp(dtp, cursor + offset);
    else if (ether_type == ETH_P_IP)
        decode_ip(dtp, cursor + offset);
    else if (ether_type == ETH_P_IPV6)
        decode_ip6(dtp, cursor + offset);
}

static void decode_raw(DAQTestPacket *dtp, const uint8_t *cursor)
{
    uint8_t ipver = (cursor[0] & 0xf0) >> 4;
    if (ipver == 4)
        return decode_ip(dtp, cursor);
    else if (ipver == 6)
        return decode_ip6(dtp, cursor);
    else
        printf("Unknown IP version on raw packet: %hhu!\n", ipver);
}

static void decode_packet(DAQTestPacket *dtp, const uint8_t *packet, const DAQ_PktHdr_t *hdr)
{
    dtp->hdr = hdr;
    dtp->packet = packet;
    switch (dlt)
    {
        case DLT_EN10MB:
            return decode_eth(dtp, packet);

        case DLT_RAW:
            return decode_raw(dtp, packet);

        default:
            printf("Unhandled datalink type: %d!\n", dlt);
    }
}

static DAQ_Verdict handle_packet_message(DAQTestThreadContext *ctxt, DAQ_Msg_h msg)
{
    const DAQ_PktHdr_t *hdr = daq_msg_get_pkthdr(msg);
    const uint8_t *data = daq_msg_get_data(msg);
    const DAQTestConfig *cfg = ctxt->cfg;

    ctxt->packet_count++;

    if (cfg->delay)
        usleep(cfg->delay * 1000);

    if (cfg->performance_mode)
        return cfg->default_verdict;

    printf("\nGot Packet! Size = %u/%u, Ingress = %d (Group = %d), Egress = %d (Group = %d), Addr Space ID = %u",
            daq_msg_get_data_len(msg), hdr->pktlen, hdr->ingress_index, hdr->ingress_group,
            hdr->egress_index, hdr->egress_group, hdr->address_space_id);
    if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
        printf(", Opaque = %u", hdr->opaque);
    if (hdr->flags & DAQ_PKT_FLAG_FLOWID_IS_VALID)
        printf(", Flow ID = %u", hdr->flow_id);
    printf("\n");

    if (hdr->flags)
    {
        printf("Flags (0x%X): ", hdr->flags);
        if (hdr->flags & DAQ_PKT_FLAG_HW_TCP_CS_GOOD)
            printf("HW_TCP_CS_GOOD ");
        if (hdr->flags & DAQ_PKT_FLAG_OPAQUE_IS_VALID)
            printf("OPAQUE_IS_VALID ");
        if (hdr->flags & DAQ_PKT_FLAG_NOT_FORWARDING)
            printf("NOT_FORWARDING ");
        if (hdr->flags & DAQ_PKT_FLAG_PRE_ROUTING)
            printf("PRE_ROUTING ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_DETECTED)
            printf("SSL_DETECTED ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_SHELLO)
            printf("SSL_SHELLO ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_SERVER_KEYX)
            printf("SSL_SERVER_KEYX ");
        if (hdr->flags & DAQ_PKT_FLAG_SSL_CLIENT_KEYX)
            printf("SSL_CLIENT_KEYX ");
        if (hdr->flags & DAQ_PKT_FLAG_IGNORE_VLAN)
            printf("IGNORE_VLAN ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_ADDRESSES)
            printf("REAL_ADDRESSES ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_SIP_V6)
            printf("REAL_SIP_V6 ");
        if (hdr->flags & DAQ_PKT_FLAG_REAL_DIP_V6)
            printf("REAL_DIP_V6 ");
        if (hdr->flags & DAQ_PKT_FLAG_FLOWID_IS_VALID)
            printf("FLOWID_IS_VALID ");
        if (hdr->flags & DAQ_PKT_FLAG_LOCALLY_DESTINED)
            printf("LOCALLY_DESTINED ");
        if (hdr->flags & DAQ_PKT_FLAG_LOCALLY_ORIGINATED)
            printf("LOCALLY_ORIGINATED ");
        if (hdr->flags & DAQ_PKT_FLAG_SCRUBBED_TCP_OPTS)
            printf("SCRUBBED_TCP_OPTS ");
        if (hdr->flags & DAQ_PKT_FLAG_HA_STATE_AVAIL)
            printf("HA_STATE_AVAIL ");
        if (hdr->flags & DAQ_PKT_FLAG_ERROR_PACKET)
            printf("ERROR_PACKET ");
        printf("\n");
    }
    if (cfg->dump_packets)
        print_hex_dump(data, daq_msg_get_data_len(msg));

    if (cfg->modify_opaque_value)
    {
        DAQ_ModFlow_t modify;

        modify.type = DAQ_MODFLOW_TYPE_OPAQUE;
        modify.length = sizeof(uint32_t);
        modify.value = &ctxt->packet_count;
        daq_instance_modify_flow(ctxt->instance, msg, &modify);
    }

    DAQTestPacket dtp;
    memset(&dtp, 0, sizeof(dtp));
    dtp.msg = msg;
    dtp.ctxt = ctxt;
    decode_packet(&dtp, data, hdr);

    return process_packet(&dtp);
}

static void handle_flow_stats_message(DAQ_Msg_h msg)
{
    const Flow_Stats_t *stats = (const Flow_Stats_t *) daq_msg_get_hdr(msg);
    char addr_str[INET6_ADDRSTRLEN];
    const struct in6_addr* tmpIp;

    if (msg->type == DAQ_MSG_TYPE_SOF)
        printf("Received SoF metapacket.\n");
    else if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("Received EoF metapacket.\n");

    printf("  Ingress:\n");
    printf("    Interface: %d\n", stats->ingressIntf);
    printf("    Zone: %d\n", stats->ingressZone);
    printf("  Egress:\n");
    printf("    Interface: %d\n", stats->egressIntf);
    printf("    Zone: %d\n", stats->egressZone);
    printf("  Protocol: %hhu\n", stats->protocol);
    printf("  VLAN: %hu\n", stats->vlan_tag);
    printf("  Opaque: %u\n", stats->opaque);
    printf("  Initiator:\n");
    tmpIp = (const struct in6_addr*)stats->initiatorIp;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP
            || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->initiatorPort));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->initiatorBytes, stats->initiatorPkts);
    printf("  Responder:\n");
    tmpIp = (const struct in6_addr*)stats->responderIp;
    if (tmpIp->s6_addr32[0] || tmpIp->s6_addr32[1] || tmpIp->s6_addr16[4] || tmpIp->s6_addr16[5] != 0xFFFF)
        inet_ntop(AF_INET6, tmpIp, addr_str, sizeof(addr_str));
    else
        inet_ntop(AF_INET, &tmpIp->s6_addr32[3], addr_str, sizeof(addr_str));
    printf("    IP: %s", addr_str);
    if (stats->protocol == IPPROTO_UDP || stats->protocol == IPPROTO_TCP
            || stats->protocol == IPPROTO_ICMP || stats->protocol == IPPROTO_ICMPV6)
        printf(":%d", ntohs(stats->responderPort));
    printf("\n");
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("    Sent: %" PRIu64 " bytes (%" PRIu64 " packets)\n", stats->responderBytes, stats->responderPkts);
    printf("  First Packet: %lu seconds, %lu microseconds\n", stats->sof_timestamp.tv_sec, stats->sof_timestamp.tv_usec);
    if (msg->type == DAQ_MSG_TYPE_EOF)
        printf("  Last Packet: %lu seconds, %lu microseconds\n", stats->eof_timestamp.tv_sec, stats->eof_timestamp.tv_usec);
}

static void print_daq_stats(DAQ_Stats_t *stats)
{
    printf("*DAQ Module Statistics*\n");
    printf("  Hardware Packets Received:  %" PRIu64 "\n", stats->hw_packets_received);
    printf("  Hardware Packets Dropped:   %" PRIu64 "\n", stats->hw_packets_dropped);
    printf("  Packets Received:   %" PRIu64 "\n", stats->packets_received);
    printf("  Packets Filtered:   %" PRIu64 "\n", stats->packets_filtered);
    printf("  Packets Passed:     %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_PASS]);
    printf("  Packets Replaced:   %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_REPLACE]);
    printf("  Packets Blocked:    %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_BLOCK]);
    printf("  Packets Injected:   %" PRIu64 "\n", stats->packets_injected);
    printf("  Flows Whitelisted:  %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_WHITELIST]);
    printf("  Flows Blacklisted:  %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_BLACKLIST]);
    printf("  Flows Ignored:      %" PRIu64 "\n", stats->verdicts[DAQ_VERDICT_IGNORE]);
}

static void print_daq_modules(void)
{
    const DAQ_VariableDesc_t *var_desc_table;
    DAQ_Module_h module;
    int num_var_descs, i;

    module = daq_modules_first();
    while (module)
    {
        printf("\n[%s]\n", daq_module_get_name(module));
        printf(" Version: %u\n", daq_module_get_version(module));
        printf(" Type: 0x%x\n", daq_module_get_type(module));
        num_var_descs = daq_module_get_variable_descs(module, &var_desc_table);
        if (num_var_descs)
        {
            printf(" Variables:\n");
            for (i = 0; i < num_var_descs; i++)
            {
                printf("  %s ", var_desc_table[i].name);
                if (var_desc_table[i].flags & DAQ_VAR_DESC_REQUIRES_ARGUMENT)
                    printf("<arg> ");
                else if (!(var_desc_table[i].flags & DAQ_VAR_DESC_FORBIDS_ARGUMENT))
                    printf("[arg] ");
                printf("- %s\n", var_desc_table[i].description);
            }
        }
        module = daq_modules_next();
    }
    printf("\n");
}

static DAQTestModuleConfig *daqtest_module_config_new(void)
{
    DAQTestModuleConfig *dtmc;

    dtmc = calloc(1, sizeof(DAQTestModuleConfig));
    if (!dtmc)
    {
        fprintf(stderr, "Failed to allocate a new DAQTest module configuration!\n\n");
        return NULL;
    }

    /* Some default values. */
    dtmc->mode = DAQ_MODE_PASSIVE;

    return dtmc;
}

static int parse_command_line(int argc, char *argv[], DAQTestConfig *cfg)
{
    DAQTestModuleConfig *dtmc;
    IPv4Addr *ip;
    const char *options = "A:c:C:d:D:f:hi:lm:M:OpP:s:t:T:vV:xz:";
    char *endptr;
    int ch;

    /* Clear configuration and initialize to defaults. */
    memset(cfg, 0, sizeof(DAQTestConfig));
    cfg->snaplen = 1518;
    cfg->default_verdict = DAQ_VERDICT_PASS;
    cfg->ping_action = PING_ACTION_PASS;
    cfg->thread_count = 1;
    cfg->module_configs = daqtest_module_config_new();
    if (!cfg->module_configs)
        return -1;
    dtmc = cfg->module_configs;

    opterr = 0;
    while ((ch = getopt(argc, argv, options)) != -1)
    {
        switch (ch)
        {
            case 'A':
                ip = calloc(1, sizeof(*ip));
                if (!ip)
                {
                    fprintf(stderr, "Failed to allocate space for an IP address!\n\n");
                    return -1;
                }
                if (!inet_pton(AF_INET, optarg, &ip->addr))
                {
                    fprintf(stderr, "Invalid IP address specified: %s\n\n", optarg);
                    free(ip);
                    return -1;
                }
                ip->next = cfg->ip_addrs;
                cfg->ip_addrs = ip;
                break;

            case 'c':
                errno = 0;
                cfg->packet_limit = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid packet limit specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'C':
                dtmc->num_variables++;
                dtmc->variables = realloc(dtmc->variables, dtmc->num_variables * sizeof(char *));
                if (!dtmc->variables)
                {
                    fprintf(stderr, "Failed to allocate space for a variable pointer!\n\n");
                    return -1;
                }
                dtmc->variables[dtmc->num_variables - 1] = optarg;
                break;

            case 'd':
                if (dtmc->module_name)
                {
                    /* Begin configuring a new module. */
                    dtmc->next = daqtest_module_config_new();
                    if (!dtmc->next)
                        return -1;
                    dtmc = dtmc->next;
                }
                dtmc->module_name = optarg;
                break;

            case 'D':
                errno = 0;
                cfg->delay = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid packet delay specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'f':
                cfg->filter = optarg;
                break;

            case 'h':
                usage();
                exit(0);

            case 'i':
                cfg->input = optarg;
                break;

            case 'l':
                cfg->list_and_exit = true;
                break;

            case 'm':
                cfg->num_module_paths++;
                cfg->module_paths = realloc(cfg->module_paths, cfg->num_module_paths * sizeof(char *));
                if (!cfg->module_paths)
                {
                    fprintf(stderr, "Failed to allocate space for a module path pointer!\n\n");
                    return -1;
                }
                cfg->module_paths[cfg->num_module_paths - 1] = optarg;
                break;

            case 'M':
                for (dtmc->mode = DAQ_MODE_PASSIVE; dtmc->mode < MAX_DAQ_MODE; dtmc->mode++)
                {
                    if (!strcmp(optarg, daq_mode_string(dtmc->mode)))
                        break;
                }
                if (dtmc->mode == MAX_DAQ_MODE)
                {
                    fprintf(stderr, "Invalid mode: %s!\n", optarg);
                    return -1;
                }
                break;

            case 'O':
                cfg->modify_opaque_value = true;
                break;

            case 'p':
                cfg->performance_mode = true;
                break;

            case 'P':
                if (!strcmp(optarg, "block"))
                    cfg->ping_action = PING_ACTION_DROP;
                else if (!strcmp(optarg, "spoof"))
                    cfg->ping_action = PING_ACTION_SPOOF;
                else if (!strcmp(optarg, "replace"))
                    cfg->ping_action = PING_ACTION_REPLACE;
                else if (!strcmp(optarg, "blacklist"))
                    cfg->ping_action = PING_ACTION_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    cfg->ping_action = PING_ACTION_WHITELIST;
                else if (!strcmp(optarg, "clone"))
                    cfg->ping_action = PING_ACTION_CLONE;
                else
                {
                    fprintf(stderr, "Invalid ping argument specified (%s)!\n\n", optarg);
                    return -1;
                }
                break;

            case 's':
                errno = 0;
                cfg->snaplen = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid snap length specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 't':
                errno = 0;
                cfg->timeout = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid receive timeout specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'T':
                errno = 0;
                cfg->timeout_limit = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0)
                {
                    fprintf(stderr, "Invalid receive timeout limit specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'v':
                cfg->verbosity++;
                break;

            case 'V':
                if (!strcmp(optarg, "pass"))
                    cfg->default_verdict = DAQ_VERDICT_PASS;
                else if (!strcmp(optarg, "block"))
                    cfg->default_verdict = DAQ_VERDICT_BLOCK;
                else if (!strcmp(optarg, "blacklist"))
                    cfg->default_verdict = DAQ_VERDICT_BLACKLIST;
                else if (!strcmp(optarg, "whitelist"))
                    cfg->default_verdict = DAQ_VERDICT_WHITELIST;
                else
                {
                    fprintf(stderr, "Invalid default verdict specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            case 'x':
                cfg->dump_packets = true;
                break;

            case 'z':
                errno = 0;
                cfg->thread_count = strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || errno != 0 || cfg->thread_count == 0)
                {
                    fprintf(stderr, "Invalid thread count specified: %s\n\n", optarg);
                    return -1;
                }
                break;

            default:
                fprintf(stderr, "Invalid argument specified (%c)!\n", ch);
                return -1;
        }
    }

    return 0;
}

static void print_config(DAQTestConfig *cfg)
{
    DAQTestModuleConfig *dtmc;
    IPv4Addr *ip;
    char addr_str[INET_ADDRSTRLEN];
    unsigned int i;

    printf("[Config]\n");
    printf("  Input: %s\n", cfg->input);
    printf("  Snaplen: %hu\n", cfg->snaplen);
    printf("  Timeout: %ums (Allowance: ", cfg->timeout);
    if (cfg->timeout_limit)
        printf("%lu)\n", cfg->timeout_limit);
    else
        printf("Unlimited)\n");
    printf("  Module Stack:\n");
    for (dtmc = cfg->module_configs, i = 0; dtmc; dtmc = dtmc->next, i++)
    {
        printf("    %u: [%s]\n", i, dtmc->module_name);
        printf("      Mode: %s\n", daq_mode_string(dtmc->mode));
        if (dtmc->variables)
        {
            printf("      Variables:\n");
            for (i = 0; i < dtmc->num_variables; i++)
                printf("        %s\n", dtmc->variables[i]);
        }
    }
    printf("  Packet Count: ");
    if (cfg->packet_limit)
        printf("%lu\n", cfg->packet_limit);
    else
        printf("Unlimited\n");
    printf("  Default Verdict: %s\n", daq_verdict_string(cfg->default_verdict));
    printf("  Ping Action: %s\n", ping_action_strings[cfg->ping_action]);
    if (cfg->ip_addrs)
    {
        printf("  Handling ARPs for:\n");
        for (ip = cfg->ip_addrs; ip; ip = ip->next)
        {
            inet_ntop(AF_INET, &ip->addr, addr_str, sizeof(addr_str));
            printf("  %s\n", addr_str);
        }
    }
    if (cfg->delay > 0)
        printf("  Delaying packets by %lu milliseconds.\n", cfg->delay);
    if (cfg->modify_opaque_value)
        printf("  Modifying the opaque value of flows to be the current packet count.\n");
    if (cfg->performance_mode)
        printf("  In performance mode, no decoding will be done!\n");
}

static void *processing_thread(void *arg)
{
    DAQTestThreadContext *ctxt = (DAQTestThreadContext *) arg;
    const DAQTestConfig *cfg = ctxt->cfg;
    DAQ_Stats_t stats;
    uint64_t recv_counters[MAX_DAQ_RSTAT];
    unsigned int i, max_recv, timeout_count;
    int rval;

    if (cfg->filter && (rval = daq_instance_set_filter(ctxt->instance, cfg->filter)) != 0)
    {
        fprintf(stderr, "Could not set BPF filter for DAQ module! (%d: %s)\n", rval, cfg->filter);
        goto exit;
    }

    if ((rval = daq_instance_start(ctxt->instance)) != DAQ_SUCCESS)
    {
        fprintf(stderr, "Could not start DAQ module: (%d: %s)\n", rval, daq_instance_get_error(ctxt->instance));
        goto exit;
    }

    printf("Snaplen: %d\n", daq_instance_get_snaplen(ctxt->instance));

    DAQ_MsgPoolInfo_t mpool_info;
    if (daq_instance_get_msg_pool_info(ctxt->instance, &mpool_info) == DAQ_SUCCESS)
    {
        printf("Message Pool Info:\n");
        printf("  Size: %u\n", mpool_info.size);
        printf("  Available: %u\n", mpool_info.available);
        printf("  Memory Usage: %zu\n", mpool_info.mem_size);
    }

    dlt = daq_instance_get_datalink_type(ctxt->instance);

    memset(recv_counters, 0, sizeof(recv_counters));
    max_recv = timeout_count = 0;
    while (!ctxt->done && (!cfg->packet_limit || ctxt->packet_count < cfg->packet_limit))
    {
        /* Check to see if a config swap is pending. */
        if (ctxt->newconfig && !ctxt->oldconfig)
        {
            void *oldconfig;
            rval = daq_instance_config_swap(ctxt->instance, ctxt->newconfig, &oldconfig);
            if (rval != DAQ_SUCCESS)
                fprintf(stderr, "Failed to swap in new config: %s (%d)", daq_instance_get_error(ctxt->instance), rval);
            ctxt->newconfig = NULL;
            ctxt->oldconfig = oldconfig;
        }

        DAQ_Msg_h msgs[16];
        DAQ_RecvStatus rstat;
        unsigned num_recv;

        num_recv = daq_instance_msg_receive(ctxt->instance, 16, msgs, &rstat);
        recv_counters[rstat]++;
        if (num_recv > max_recv)
            max_recv = num_recv;

        for (unsigned idx = 0; idx < num_recv; idx++)
        {
            DAQ_Msg_h msg = msgs[idx];
            DAQ_Verdict verdict = DAQ_VERDICT_PASS;
            switch (msg->type)
            {
                case DAQ_MSG_TYPE_PACKET:
                    verdict = handle_packet_message(ctxt, msg);
                    break;
                case DAQ_MSG_TYPE_SOF:
                case DAQ_MSG_TYPE_EOF:
                    handle_flow_stats_message(msg);
                    break;
                default:
                    break;
            }
            daq_instance_msg_finalize(ctxt->instance, msg, verdict);
        }

        if (rstat != DAQ_RSTAT_OK && rstat != DAQ_RSTAT_WOULD_BLOCK)
        {
            if (rstat == DAQ_RSTAT_TIMEOUT)
            {
                timeout_count++;
                if (!cfg->timeout_limit || timeout_count < cfg->timeout_limit)
                    continue;
            }
            else if (rstat == DAQ_RSTAT_EOF)
                printf("Read the entire file!\n");
            else if (rstat == DAQ_RSTAT_NOBUF)
                printf("Ran out of buffers to use, this really shouldn't happen...\n");
            else if (rstat == DAQ_RSTAT_ERROR)
                fprintf(stderr, "Error receiving messages: %s\n", daq_instance_get_error(ctxt->instance));
            break;
        }
    }

    printf("\nDAQ receive timed out %u times.\n", timeout_count);
    printf("Maximum messages received in a burst: %u\n", max_recv);

    printf("\n*Receive Status Counters*\n");
    const char *recv_status_string[MAX_DAQ_RSTAT] = {
        "Ok",           // DAQ_RSTAT_OK
        "Would Block",  // DAQ_RSTAT_WOULD_BLOCK
        "Timeout",      // DAQ_RSTAT_TIMEOUT
        "End of File",  // DAQ_RSTAT_EOF
        "Interrupted",  // DAQ_RSTAT_INTERRUPTED
        "No Buffers",   // DAQ_RSTAT_NOBUF
        "Error",        // DAQ_RSTAT_ERROR
        "Invalid",      // DAQ_RSTAT_INVALID
    };
    for (i = 0; i < MAX_DAQ_RSTAT; i++)
    {
        if (recv_counters[i])
            printf("  %s: %" PRIu64 "\n", recv_status_string[i], recv_counters[i]);
    }
    printf("\n");

    if ((rval = daq_instance_get_stats(ctxt->instance, &stats)) != 0)
        fprintf(stderr, "Could not get DAQ module stats: (%d: %s)\n", rval, daq_instance_get_error(ctxt->instance));
    else
        print_daq_stats(&stats);

    daq_instance_stop(ctxt->instance);

exit:
    ctxt->exited = true;

    return NULL;
}

static int create_daq_config(DAQTestConfig *cfg, DAQ_Config_h *daqcfg_ptr)
{
    int rval;

    if ((rval = daq_config_new(daqcfg_ptr)) != DAQ_SUCCESS)
    {
        fprintf(stderr, "Error allocating a new DAQ configuration object! (%d)\n", rval);
        return rval;
    }

    DAQTestModuleConfig *dtmc;
    DAQ_Config_h daqcfg = *daqcfg_ptr;

    daq_config_set_input(daqcfg, cfg->input);
    daq_config_set_snaplen(daqcfg, cfg->snaplen);
    daq_config_set_timeout(daqcfg, cfg->timeout);

    for (dtmc = cfg->module_configs; dtmc; dtmc = dtmc->next)
    {
        DAQ_Module_h module = daq_find_module(dtmc->module_name);
        if (!module)
        {
            fprintf(stderr, "Could not find requested module: %s!\n", dtmc->module_name);
            return -1;
        }

        DAQ_ModuleConfig_h modcfg;
        if ((rval = daq_module_config_new(&modcfg, module)) != DAQ_SUCCESS)
        {
            fprintf(stderr, "Error allocating a new DAQ module configuration object! (%d)\n", rval);
            return rval;
        }

        daq_module_config_set_mode(modcfg, dtmc->mode);

        for (unsigned i = 0; i < dtmc->num_variables; i++)
        {
            char *key = dtmc->variables[i];
            char *value = strchr(key, '=');
            if (value)
            {
                *value = '\0';
                value++;
                if (*value == '\0')
                    value = NULL;
            }
            if ((rval = daq_module_config_set_variable(modcfg, key, value)) != DAQ_SUCCESS)
            {
                fprintf(stderr, "Error setting DAQ configuration variable with key '%s' and value '%s'! (%d)", key, value, rval);
                return rval;
            }
        }
        if ((rval = daq_config_push_module_config(daqcfg, modcfg)) != DAQ_SUCCESS)
        {
            fprintf(stderr, "Error pushing DAQ module configuration for '%s' onto the DAQ config! (%d)\n", dtmc->module_name, rval);
            return rval;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    DAQTestConfig cfg;
    DAQ_Config_h daqcfg;
    int rval;

    if ((rval = parse_command_line(argc, argv, &cfg)) != 0)
        return rval;

    if ((!cfg.input || !cfg.module_configs->module_name) && !cfg.list_and_exit)
    {
        usage();
        return -1;
    }

    daq_set_verbosity(cfg.verbosity);
#ifdef USE_STATIC_MODULES
    daq_load_static_modules(static_modules);
#endif
    daq_load_dynamic_modules(cfg.module_paths);

    if (cfg.list_and_exit)
    {
        print_daq_modules();
        return 0;
    }

    print_config(&cfg);

    initialize_static_data();
    printf("Local MAC Address: ");
    print_mac(local_mac_addr);
    printf("\n");

    if ((rval = create_daq_config(&cfg, &daqcfg)) != DAQ_SUCCESS)
        return rval;

    /* Allocate the packet thread contexts and instantiate a DAQ instance for each. */
    DAQTestThreadContext *threads = calloc(cfg.thread_count, sizeof(*threads));

    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        char errbuf[256];

        if ((rval = daq_instance_initialize(daqcfg, &dttc->instance, errbuf, sizeof(errbuf))) != 0)
        {
            fprintf(stderr, "Could not initialize DAQ module: (%d: %s)\n", rval, errbuf);
            return -1;
        }

        dttc->cfg = &cfg;
    }

    /* Free the configuration object's memory. */
    daq_config_destroy(daqcfg);

    /* Set up the main thread to handle signals. */
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = handler;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    /* Spin off all of the packet threads (blocking the signals we're catching). */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        if ((rval = pthread_create(&dttc->tid, NULL, processing_thread, dttc)) != 0)
        {
            fprintf(stderr, "Error creating thread: %s (%d)\n", strerror(errno), errno);
            return -1;
        }
    }
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);

    /* Start the main loop. */
    const struct timespec main_sleep = { 0, 1000000 }; // 0.001 sec
    bool notdone;
    do
    {
        if (pending_signal)
        {
            switch (pending_signal)
            {
                case SIGTERM:
                case SIGINT:
                    printf("Sending breakloop to all instances.\n");
                    for (unsigned i = 0; i < cfg.thread_count; i++)
                    {
                        DAQTestThreadContext *dttc = &threads[i];
                        dttc->done = true;
                        daq_instance_breakloop(dttc->instance);
                    }
                    break;

                case SIGHUP:
                    printf("Loading config and signaling a swap for all instances.\n");
                    for (unsigned i = 0; i < cfg.thread_count; i++)
                    {
                        DAQTestThreadContext *dttc = &threads[i];
                        if (dttc->newconfig || dttc->oldconfig)
                        {
                            printf("Skipping config reload for instance %u as it is still reloading.\n", i);
                            continue;
                        }
                        void *newconfig;
                        if ((rval = daq_instance_config_load(dttc->instance, &newconfig)) == DAQ_SUCCESS)
                            dttc->newconfig = newconfig;
                        else if (rval != DAQ_ERROR_NOTSUP)
                            fprintf(stderr, "Failed to load new config for instance %u: %d", i, rval);
                    }
                    break;

                default:
                    printf("Received unrecognized signal: %d\n", pending_signal);
            }
            pending_signal = 0;
        }

        nanosleep(&main_sleep, NULL);

        /* Check if any threads are still running and perform other housekeeping... */
        notdone = false;
        for (unsigned i = 0; i < cfg.thread_count; i++)
        {
            DAQTestThreadContext *dttc = &threads[i];
            if (dttc->oldconfig)
            {
                rval = daq_instance_config_free(dttc->instance, dttc->oldconfig);
                if (rval != DAQ_SUCCESS)
                    fprintf(stderr, "Failed to free old config for instance %u: %d", i, rval);
                dttc->oldconfig = NULL;
            }
            if (!dttc->exited)
                notdone = true;
        }
    } while (notdone);

    /* Clean up all of the packet threads and tear down their DAQ instances. */
    for (unsigned i = 0; i < cfg.thread_count; i++)
    {
        DAQTestThreadContext *dttc = &threads[i];
        if ((rval = pthread_join(dttc->tid, NULL)) != 0)
        {
            fprintf(stderr, "Error joining thread: %s (%d)\n", strerror(errno), errno);
            return -1;
        }
        daq_instance_shutdown(dttc->instance);
    }

    return 0;
}

