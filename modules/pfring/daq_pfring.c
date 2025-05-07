/*

** Copyright (C) 2025 ENEO TECNOLOGIA S.L.
** Author: Miguel Álvarez <malvarez@redborder.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <pfring.h>
#include <net/ethernet.h>

#include "daq_module_api.h"

#ifdef LIBPCAP_AVAILABLE
static pthread_mutex_t bpf_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define DAQ_PFRING_VERSION 1
#define PF_RING_CLUSTER_ID 99
#define DEFAULT_POOL_SIZE 32
#define MAX_DEVICE_PAIRS 16
#define MAX_DEVICE_NAME_LEN 16
#define PFRING_MAX_APP_NAME_LEN 64

/* Define u_char if not already defined */
#ifndef u_char
typedef unsigned char u_char;
#endif

typedef struct PfringPktDesc {
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    struct PfringPktDesc *next;
} PfringPktDesc;

typedef struct {
    PfringPktDesc *pool;
    PfringPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} PfringMsgPool;

typedef struct {
    char name[MAX_DEVICE_NAME_LEN];
    int index;
    pfring *ring;
    bool active;
    int peer_index;
} PfringDevice;

typedef struct {
    char *device;
    unsigned snaplen;
    int promisc;
    int buffer_size;
    DAQ_Mode mode;
    
    PfringDevice devices[MAX_DEVICE_PAIRS * 2];
    uint32_t device_count;
    uint32_t pair_count;
    
    uint32_t cluster_id;
    uint32_t cluster_type;
    
    DAQ_ModuleInstance_h modinst;
    DAQ_Stats_t stats;
    PfringMsgPool pool;
    volatile bool interrupted;

    int watermark;
    u_int8_t use_fast_tx;
    pfring_stat hw_stats;

    int curr_device_index;
    
    int timeout;
} PfringContext;

typedef struct _pfring_instance {
    struct _pfring_instance *next;
    char *name;
    int index;
    struct _pfring_instance *peer;
    pfring *ring;
    bool active;
} PfringInstance;

static int parse_interface_name(const char *input, char *intf, size_t intf_size, size_t *consumed);
static int add_device(PfringContext *pc, const char *device_name);
static int create_bridge(PfringContext *pc, const int *device_indices, size_t num_devices);
static int validate_interface_config(PfringContext *pc);
static pthread_t get_thread_id(void);
static uint16_t get_device_queue_id(uint32_t device_index);

static DAQ_BaseAPI_t daq_base_api;

static int create_packet_pool(PfringContext *pc, unsigned size) {
    PfringMsgPool *pool = &pc->pool;
    memset(pool, 0, sizeof(PfringMsgPool));
    
    size = size * 4;
    
    pool->pool = calloc(size, sizeof(PfringPktDesc));
    if (!pool->pool) {
        return DAQ_ERROR_NOMEM;
    }
    
    pool->info.size = size;
    pool->info.available = size;
    pool->info.mem_size = size * sizeof(PfringPktDesc);

    for (unsigned i = 0; i < size; i++) {
        PfringPktDesc *desc = &pool->pool[i];
        desc->data = malloc(pc->snaplen);
        if (!desc->data) {
            for (unsigned j = 0; j < i; j++) {
                free(pool->pool[j].data);
                pool->pool[j].data = NULL;
            }
            free(pool->pool);
            return DAQ_ERROR_NOMEM;
        }
        pool->info.mem_size += pc->snaplen;
        
        desc->msg.type = DAQ_MSG_TYPE_PACKET;
        desc->msg.hdr_len = sizeof(DAQ_PktHdr_t);
        desc->msg.hdr = &desc->pkthdr;
        desc->msg.data = desc->data;
        desc->msg.owner = pc->modinst;
        desc->msg.priv = desc;
        desc->next = NULL;

        desc->next = pool->freelist;
        pool->freelist = desc;
    }
    return DAQ_SUCCESS;
}

static void destroy_packet_pool(PfringContext *pc) {
    PfringMsgPool *pool = &pc->pool;
    
    if (pool->pool) {
        for (unsigned i = 0; i < pool->info.size; i++) {
            PfringPktDesc *desc = &pool->pool[i];
            if (desc->next == NULL) {
                desc->next = pool->freelist;
                pool->freelist = desc;
            }
        }
        
        for (unsigned i = 0; i < pool->info.size; i++) {
            if (pool->pool[i].data) {
                free(pool->pool[i].data);
                pool->pool[i].data = NULL;
            }
        }
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

static int pfring_daq_module_load(const DAQ_BaseAPI_t *base_api) {
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

static int parse_interface_name(const char *input, char *intf, size_t intf_size, size_t *consumed) {
    size_t len = strcspn(input, ":");
    
    if (len >= intf_size) {
        return DAQ_ERROR;
    }
    
    if (len == 0) {
        *consumed = 1;
        return DAQ_ERROR;
    }
    
    snprintf(intf, len + 1, "%s", input);
    *consumed = len;
    return DAQ_SUCCESS;
}

static int add_device(PfringContext *pc, const char *device_name) {
    if (pc->device_count >= MAX_DEVICE_PAIRS * 2) {
        return DAQ_ERROR;
    }

    if (strncmp(device_name, "zc:", 3) == 0) {
        daq_base_api.set_errbuf(pc->modinst, "ZC is not supported by daq_pfring. Please use daq_pfring_zc");
        return DAQ_ERROR;
    }

    PfringDevice *dev = &pc->devices[pc->device_count];
    snprintf(dev->name, MAX_DEVICE_NAME_LEN, "%s", device_name);
    
    uint32_t flags = PF_RING_LONG_HEADER;
    if (pc->promisc) {
        flags |= PF_RING_PROMISC;
    }
    if (pc->use_fast_tx) {
        flags |= PF_RING_RX_PACKET_BOUNCE;
    }
    
    dev->ring = pfring_open(device_name, pc->snaplen, flags);
    if (!dev->ring) {
        daq_base_api.set_errbuf(pc->modinst, "pfring_open(): unable to open device '%s'", device_name);
        return DAQ_ERROR;
    }

    dev->index = pc->device_count;
    dev->active = false;
    dev->peer_index = -1;
    
    pc->device_count++;
    return DAQ_SUCCESS;
}

static int create_bridge(PfringContext *pc, const int *device_indices, size_t num_devices) {
    if (!pc || !device_indices || num_devices < 2) {
        return DAQ_ERROR;
    }

    for (size_t i = 0; i < num_devices; i++) {
        if (device_indices[i] < 0 || (uint32_t)device_indices[i] >= pc->device_count) {
            return DAQ_ERROR;
        }
    }

    /* For inline mode, we only need to set up peer indices between pairs */
    for (size_t i = 0; i < num_devices; i++) {
        int next_index = (i + 1) % num_devices;
        int current_idx = device_indices[i];
        int next_idx = device_indices[next_index];

        pc->devices[current_idx].peer_index = next_idx;
        pc->devices[current_idx].active = true;
    }
    
    pc->pair_count++;    
    return DAQ_SUCCESS;
}

static int validate_interface_config(PfringContext *pc) {
    if (pc->device_count == 0) {
        return DAQ_ERROR;
    }

    if (pc->mode == DAQ_MODE_INLINE) {
        if (pc->device_count % 2 != 0) {
            return DAQ_ERROR;
        }
        for (uint32_t i = 0; i < pc->device_count; i++) {
            if (pc->devices[i].peer_index == -1) {
                return DAQ_ERROR;
            }
        }
    }
    else if (pc->mode == DAQ_MODE_PASSIVE) {
        if (pc->device_count == 0) {
            return DAQ_ERROR;
        }
    }

    return DAQ_SUCCESS;
}

static int pfring_daq_instantiate(const DAQ_ModuleConfig_h modcfg, 
                                 DAQ_ModuleInstance_h modinst,
                                 void **ctxt_ptr)
{
    PfringContext *pc;
    const char *dev_ptr;
    size_t consumed;
    char intf[IFNAMSIZ];
    int ret;

    pc = calloc(1, sizeof(PfringContext));
    if (!pc) {
        daq_base_api.set_errbuf(modinst, "Failed to allocate context");
        return DAQ_ERROR_NOMEM;
    }

    pc->modinst = modinst;
    pc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    pc->mode = daq_base_api.config_get_mode(modcfg);

    /* Force inline mode if we have multiple interfaces */
    const char *device_str = daq_base_api.config_get_input(modcfg);
    if (strchr(device_str, ':')) {
        pc->mode = DAQ_MODE_INLINE;
    }

    pc->promisc = PF_RING_PROMISC;
    pc->cluster_id = PF_RING_CLUSTER_ID;
    pc->cluster_type = 0;
    pc->watermark = 0;
    pc->use_fast_tx = 0;
    pc->device_count = 0;
    pc->pair_count = 0;
    pc->curr_device_index = 0;
    pc->interrupted = false;
    
    pc->timeout = 1000;

    const char *cluster_id_str = daq_base_api.config_get_variable(modcfg, "cluster_id");
    if (cluster_id_str) pc->cluster_id = atoi(cluster_id_str);

    const char *no_promisc = daq_base_api.config_get_variable(modcfg, "no_promisc");
    pc->promisc = no_promisc ? 0 : PF_RING_PROMISC;

    const char *cluster_mode_str = daq_base_api.config_get_variable(modcfg, "cluster_mode");
    pc->cluster_type = cluster_mode_str ? atoi(cluster_mode_str) : cluster_per_flow;

    const char *watermark_str = daq_base_api.config_get_variable(modcfg, "watermark");
    if (watermark_str) pc->watermark = atoi(watermark_str);

    const char *fast_tx_str = daq_base_api.config_get_variable(modcfg, "fast_tx");
    pc->use_fast_tx = fast_tx_str ? 1 : 0;
    
    const char *timeout_str = daq_base_api.config_get_variable(modcfg, "timeout");
    if (timeout_str) pc->timeout = atoi(timeout_str);

    pc->device = strdup(device_str);
    if (!pc->device) {
        daq_base_api.set_errbuf(modinst, "Failed to allocate device string");
        free(pc);
        return DAQ_ERROR_NOMEM;
    }

    dev_ptr = pc->device;
    int current_pair[MAX_DEVICE_PAIRS];
    int pair_count = 0;

    while (*dev_ptr) {
        ret = parse_interface_name(dev_ptr, intf, sizeof(intf), &consumed);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to parse interface name");
            free(pc);
            return DAQ_ERROR;
        }

        ret = add_device(pc, intf);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to add interface");
            free(pc);
            return DAQ_ERROR;
        }

        current_pair[pair_count++] = pc->device_count - 1;

        dev_ptr += consumed;
        if (*dev_ptr == ':') {
            dev_ptr++;
            if (pc->mode == DAQ_MODE_INLINE && pair_count >= 2) {
                ret = create_bridge(pc, current_pair, pair_count);
                if (ret != DAQ_SUCCESS) {
                    daq_base_api.set_errbuf(modinst, "Failed to create bridge between interfaces");
                    free(pc);
                    return DAQ_ERROR;
                }
                pair_count = 0;
            }
        }
    }

    /* Handle any remaining devices in the last pair */
    if (pc->mode == DAQ_MODE_INLINE && pair_count >= 2) {
        ret = create_bridge(pc, current_pair, pair_count);
        if (ret != DAQ_SUCCESS) {
            daq_base_api.set_errbuf(modinst, "Failed to create bridge between interfaces");
            free(pc);
            return DAQ_ERROR;
        }
    }

    if (validate_interface_config(pc) != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Invalid interface configuration");
        free(pc);
        return DAQ_ERROR;
    }

    ret = create_packet_pool(pc, DEFAULT_POOL_SIZE);
    if (ret != DAQ_SUCCESS) {
        daq_base_api.set_errbuf(modinst, "Failed to create packet pool");
        free(pc);
        return ret;
    }

    *ctxt_ptr = pc;
    return DAQ_SUCCESS;
}

/*
    Snort spawning multiple threads causes issues... :/
*/
static pthread_t get_thread_id(void) {
    return pthread_self();
}

static uint16_t get_device_queue_id(uint32_t device_index) {
    pthread_t thread_id = get_thread_id();
    uint16_t base_queue_id = 1 + ((uint16_t)((uintptr_t)thread_id % 32767));
    uint16_t device_queue_id = base_queue_id + (1000 * device_index);  
    return device_queue_id;
}

static inline int find_packet(PfringContext *pc, struct pfring_pkthdr *hdr, u_char **pkt_data) {
    if (pc->interrupted) {
        pc->interrupted = false;
        return -1;
    }

    int start_idx = pc->curr_device_index;
    
    do {
        PfringDevice *device = &pc->devices[pc->curr_device_index];
        
        if (device->active && device->ring) {
            int rc = pfring_recv(device->ring, pkt_data, 0, hdr, 0);
            
            if (rc == 1) {
                return 1;
            }
        }
        
        pc->curr_device_index = (pc->curr_device_index + 1) % pc->device_count;
    } while (pc->curr_device_index != start_idx);
    
    return 0;
}

static inline DAQ_RecvStatus wait_for_packet(PfringContext *pc, int timeout) {
    struct pollfd pfd[MAX_DEVICE_PAIRS * 2];
    int num_fds = 0;
    
    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].active && pc->devices[i].ring) {
            pfd[num_fds].fd = pfring_get_selectable_fd(pc->devices[i].ring);
            pfd[num_fds].events = POLLIN;
            pfd[num_fds].revents = 0;
            num_fds++;
        }
    }
    
    if (num_fds == 0) {
        return DAQ_RSTAT_ERROR;
    }
    
    int remaining_timeout = timeout;
    int chunk_timeout;
    
    while (remaining_timeout != 0) {
        if (pc->interrupted) {
            pc->interrupted = false;
            return DAQ_RSTAT_INTERRUPTED;
        }
        
        if (remaining_timeout > 1000 || remaining_timeout < 0) {
            chunk_timeout = 1000;
            if (remaining_timeout > 0)
                remaining_timeout -= 1000;
        } else {
            chunk_timeout = remaining_timeout;
            remaining_timeout = 0;
        }
        
        int ret = poll(pfd, num_fds, chunk_timeout);
        
        if (ret > 0) {
            for (int i = 0; i < num_fds; i++) {
                if (pfd[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                    return DAQ_RSTAT_ERROR;
                }
            }
            return DAQ_RSTAT_OK;
        } else if (ret < 0) {
            if (errno != EINTR) {
                return DAQ_RSTAT_ERROR;
            }
        }
    }
    
    return DAQ_RSTAT_TIMEOUT;
}

static int pfring_daq_start(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }
    
    pthread_t thread_id = get_thread_id();
    
    if (pc->cluster_id == 0) {
        pc->cluster_id = PF_RING_CLUSTER_ID;
    }

    for (uint32_t i = 0; i < pc->device_count; i++) {
        PfringDevice *device = &pc->devices[i];
        char app_name[PFRING_MAX_APP_NAME_LEN];
        snprintf(app_name, sizeof(app_name) - 1, "snort-cluster-%d-thread-%lu-dev-%s", 
                pc->cluster_id, (unsigned long)thread_id, device->name);
        app_name[sizeof(app_name) - 1] = '\0';
        
        pfring_set_application_name(device->ring, app_name);
        
        uint16_t queue_id = get_device_queue_id(i);
        cluster_type cluster_type_to_use = pc->cluster_type;
        if (cluster_type_to_use == 0) {
            cluster_type_to_use = cluster_per_flow_5_tuple;
        }
        
        int cluster_result = -1;
        
        uint32_t options = 0;
        
        cluster_result = pfring_set_cluster_consumer(device->ring, pc->cluster_id, queue_id, 
                                                    cluster_type_to_use, options);
        
        if (cluster_result != 0) {
            cluster_type fallback_type = cluster_per_flow;            
            cluster_result = pfring_set_cluster_consumer(device->ring, pc->cluster_id, queue_id, 
                                                        fallback_type, options);
            
            if (cluster_result != 0) {
                uint32_t device_cluster_id = pc->cluster_id + i + 100;
                
                cluster_result = pfring_set_cluster_consumer(device->ring, device_cluster_id, queue_id, 
                                                           fallback_type, options);
                
                if (cluster_result != 0) {
                    cluster_result = pfring_set_cluster(device->ring, device_cluster_id, fallback_type);
                    
                    if (cluster_result != 0) {
                        daq_base_api.set_errbuf(pc->modinst, "Cluster setup failed for device '%s' (%d)", 
                                              device->name, cluster_result);
                        
                        for (uint32_t j = 0; j < i; j++) {
                            pfring_remove_from_cluster(pc->devices[j].ring);
                        }
                        
                        return DAQ_ERROR;
                    }
                }
            }
        }

        if (pc->mode == DAQ_MODE_PASSIVE) {
            pfring_set_socket_mode(device->ring, recv_only_mode);
        } else if (pc->mode == DAQ_MODE_INLINE) {
            pfring_set_socket_mode(device->ring, send_and_recv_mode);
        } else {
            pfring_set_socket_mode(device->ring, send_and_recv_mode);
        }

        if (pc->watermark == 0) {
            pc->watermark = 1;
        }
        pfring_set_poll_watermark(device->ring, pc->watermark);

        pfring_set_filtering_mode(device->ring, software_only);

        if (pc->mode == DAQ_MODE_INLINE) {
            pfring_set_direction(device->ring, rx_only_direction);
        } else if (pc->mode == DAQ_MODE_PASSIVE) {
            pfring_set_direction(device->ring, rx_and_tx_direction);
        } else {
            pfring_set_direction(device->ring, rx_and_tx_direction);
        }
    }

    for (uint32_t i = 0; i < pc->device_count; i++) {
        PfringDevice *device = &pc->devices[i];
        
        int enable_result = pfring_enable_ring(device->ring);
        if (enable_result != 0) {
            daq_base_api.set_errbuf(pc->modinst, "Failed to enable ring for device '%s'", device->name);
            
            for (uint32_t j = 0; j < i; j++) {
                pfring_disable_ring(pc->devices[j].ring);
            }
            return DAQ_ERROR;
        }
        
        device->active = true;
    }

    /* Reset statistics */
    memset(&pc->stats, 0, sizeof(DAQ_Stats_t));
    
    return DAQ_SUCCESS;
}

static inline int pfring_transmit_packet(PfringContext *pc, PfringDevice *egress, const uint8_t *packet_data, unsigned int len)
{
    if (!egress || !egress->ring)
        return DAQ_ERROR;

    if (pc->use_fast_tx) {
        if (pfring_send_last_rx_packet(egress->ring, egress->index) < 0) {
            pc->stats.hw_packets_dropped++;
            return DAQ_ERROR;
        }
    } else {
        if (pfring_send(egress->ring, (char *)(uintptr_t)packet_data, len, 1 /* flush packet */) < 0) {
            pc->stats.hw_packets_dropped++;
            return DAQ_ERROR;
        }
    }

    pc->stats.packets_injected++;
    return DAQ_SUCCESS;
}

static unsigned pfring_daq_msg_receive(void *handle, const unsigned max_recv,
                                      const DAQ_Msg_t *msgs[], DAQ_RecvStatus *rstat) 
{
    PfringContext *pc = (PfringContext *)handle;
    struct pfring_pkthdr hdr;
    u_char *pkt_data;
    unsigned count = 0;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    
    while (count < max_recv) 
    {
        if (pc->interrupted) {
            pc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }
        
        PfringPktDesc *desc = pc->pool.freelist;
        if (!desc) {
            if (pc->stats.packets_outstanding > 0) {
                status = DAQ_RSTAT_NOBUF;
                break;
            }
            daq_base_api.set_errbuf(pc->modinst, "No packet descriptors available");
            status = DAQ_RSTAT_ERROR;
            break;
        }

        // Try to find a packet on any device
        int rc = find_packet(pc, &hdr, &pkt_data);
        
        if (rc == 1) {
            // Got a packet, process it
            uint32_t copy_len = (hdr.caplen > pc->snaplen) ? pc->snaplen : hdr.caplen;
            
            memcpy(desc->data, pkt_data, copy_len);
            
            desc->pkthdr.ts = hdr.ts;
            desc->pkthdr.pktlen = hdr.len;
            desc->pkthdr.ingress_index = pc->curr_device_index;
            desc->pkthdr.egress_index = pc->devices[pc->curr_device_index].peer_index;
            desc->pkthdr.ingress_group = -1;
            desc->pkthdr.egress_group = -1;
            desc->pkthdr.flags = 0;
            desc->msg.data_len = copy_len;
            desc->msg.priv = desc;

            pc->pool.freelist = desc->next;
            desc->next = NULL;
            
            msgs[count++] = &desc->msg;
            
            pc->stats.packets_received++;
            pc->stats.packets_outstanding++;
            pc->pool.info.available--;
        } else if (rc == -1) {
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        } else {            
            if (count == 0) {
                status = wait_for_packet(pc, pc->timeout);
                if (status != DAQ_RSTAT_OK)
                    break;
            } else {
                status = DAQ_RSTAT_WOULD_BLOCK;
                break;
            }
        }
    }
    
    *rstat = status;
    return count;
}

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS        /* DAQ_VERDICT_IGNORE */
};

static int pfring_daq_msg_finalize(void *handle, const DAQ_Msg_t *msg, DAQ_Verdict verdict)
{
    PfringContext *pc = (PfringContext *)handle;
    PfringPktDesc *desc = (PfringPktDesc *)msg->priv;

    /* Sanitize and enact the verdict. */
    if (verdict >= MAX_DAQ_VERDICT)
        verdict = DAQ_VERDICT_PASS;
    pc->stats.verdicts[verdict]++;
    pc->stats.packets_outstanding--;

    /* Apply the verdict translation table */
    verdict = verdict_translation_table[verdict];

    if (verdict == DAQ_VERDICT_PASS) {
        if (desc->pkthdr.egress_index < 0 || (uint32_t)desc->pkthdr.egress_index >= pc->device_count) {
            return DAQ_ERROR;
        }

        PfringDevice *peer = &pc->devices[desc->pkthdr.egress_index];
        if (peer == NULL) {
            return DAQ_ERROR;
        }

        if (pfring_transmit_packet(pc, peer, desc->data, desc->msg.data_len) != DAQ_SUCCESS) {
            pc->stats.hw_packets_dropped++;
        }
    }
    /* For other verdicts (like DAQ_VERDICT_BLOCK), we simply don't forward the packet */

    /* Return the descriptor to the free list */
    desc->next = pc->pool.freelist;
    pc->pool.freelist = desc;
    pc->pool.info.available++;
    return DAQ_SUCCESS;
}

static int pfring_daq_ioctl(void *handle, DAQ_IoctlCmd cmd, void *arg, size_t arglen)
{
    PfringContext *pc = (PfringContext *)handle;

    /* Only supports GET_DEVICE_INDEX for now */
    if (cmd != DIOCTL_GET_DEVICE_INDEX || arglen != sizeof(DIOCTL_QueryDeviceIndex))
        return DAQ_ERROR_NOTSUP;

    DIOCTL_QueryDeviceIndex *qdi = (DIOCTL_QueryDeviceIndex *)arg;

    if (!qdi->device)
    {
        daq_base_api.set_errbuf(pc->modinst, "No device name to find the index of!");
        return DAQ_ERROR_INVAL;
    }

    for (uint32_t i = 0; i < pc->device_count; i++)
    {
        if (!strcmp(qdi->device, pc->devices[i].name))
        {
            qdi->index = pc->devices[i].index;
            return DAQ_SUCCESS;
        }
    }

    return DAQ_ERROR_NODEV;
}

static int pfring_daq_get_stats(void *handle, DAQ_Stats_t *stats) {
    PfringContext *pc = (PfringContext *)handle;
    *stats = pc->stats;
    for(uint32_t i = 0; i < pc->device_count; i++) {
        pfring_stats(pc->devices[i].ring, &pc->hw_stats);
        stats->hw_packets_received += pc->hw_stats.recv;
        stats->hw_packets_dropped += pc->hw_stats.drop;
    }
    return DAQ_SUCCESS;
}

static int pfring_daq_stop(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return DAQ_ERROR;
    }
    
    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].active) {
            pc->devices[i].active = false;
        }
    }

    return DAQ_SUCCESS;
}

static int pfring_daq_interrupt(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    pc->interrupted = true;
    return DAQ_SUCCESS;
}

static void pfring_daq_destroy(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    if (!pc) {
        return;
    }
    
    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].ring) {
            pfring_close(pc->devices[i].ring);
            pc->devices[i].ring = NULL;
        }
    }
    
    destroy_packet_pool(pc);
    free(pc);
}

static int pfring_daq_get_datalink_type(void *handle) {
    return DLT_EN10MB;
}

static uint32_t pfring_daq_get_capabilities(void *handle) {
    return DAQ_CAPA_BPF | DAQ_CAPA_INTERRUPT | DAQ_CAPA_INJECT | DAQ_CAPA_REPLACE |
           DAQ_CAPA_UNPRIV_START | DAQ_CAPA_DEVICE_INDEX | DAQ_CAPA_BLOCK |
           DAQ_CAPA_WHITELIST | DAQ_CAPA_BLACKLIST;
}

static int pfring_daq_get_msg_pool_info(void *handle, DAQ_MsgPoolInfo_t *info) {
    if (!handle || !info)
        return DAQ_ERROR_INVAL;
    PfringContext *pc = (PfringContext *)handle;
    *info = pc->pool.info;
    return DAQ_SUCCESS;
}

static int pfring_daq_set_filter(void *handle, const char *filter) {
    PfringContext *pc = (PfringContext *)handle;
    struct bpf_program fcode;
    
#ifdef LIBPCAP_AVAILABLE
    pthread_mutex_lock(&bpf_mutex);
    if (pcap_compile_nopcap(pc->snaplen, DLT_EN10MB, &fcode,
                            filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        pthread_mutex_unlock(&bpf_mutex);
        daq_base_api.set_errbuf(pc->modinst, "BPF compilation failed");
        return DAQ_ERROR;
    }
    pthread_mutex_unlock(&bpf_mutex);
#else
    return DAQ_ERROR_NOTSUP;
#endif

    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].active && pc->devices[i].ring) {
            if (pfring_set_bpf_filter(pc->devices[i].ring, filter) < 0) {
                pcap_freecode(&fcode);
                daq_base_api.set_errbuf(pc->modinst, "Failed to set BPF filter on device %s", pc->devices[i].name);
                return DAQ_ERROR;
            }
        }
    }

    pcap_freecode(&fcode);
    return DAQ_SUCCESS;
}

static DAQ_VariableDesc_t pfring_variable_descs[] = {
    { "no_promisc", "Disable promiscuous mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "cluster_id", "PF_RING cluster ID", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "cluster_mode", "Cluster mode (2,4,5,6)", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "watermark", "Poll watermark", DAQ_VAR_DESC_REQUIRES_ARGUMENT },
    { "fast_tx", "Enable fast TX mode", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { NULL, NULL, 0 }
};

static int pfring_daq_get_variable_descs(const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = pfring_variable_descs;

    return sizeof(pfring_variable_descs) / sizeof(DAQ_VariableDesc_t);
}

static void pfring_daq_reset_stats(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    pfring_stat ps;

    memset(&pc->stats, 0, sizeof(DAQ_Stats_t));
    memset(&ps, 0, sizeof(pfring_stat));

    for (uint32_t i = 0; i < pc->device_count; i++) {
        if (pc->devices[i].ring) {
            pfring_stats(pc->devices[i].ring, &ps);
        }
    }
}

static int pfring_daq_get_snaplen(void *handle) {
    PfringContext *pc = (PfringContext *)handle;
    
    if (!pc) {
        return DAQ_ERROR;
    }
    
    return pc->snaplen;
}

static int pfring_daq_inject(void *handle, DAQ_MsgType type, const void *hdr, const uint8_t *data, uint32_t data_len)
{
    PfringContext *pc = (PfringContext *)handle;

    if (type != DAQ_MSG_TYPE_PACKET)
        return DAQ_ERROR_NOTSUP;

    const DAQ_PktHdr_t *pkthdr = (const DAQ_PktHdr_t *)hdr;
    if (pkthdr->ingress_index < 0 || (uint32_t)pkthdr->ingress_index >= pc->device_count)
        return DAQ_ERROR;

    PfringDevice *device = &pc->devices[pkthdr->ingress_index];
    if (pfring_transmit_packet(pc, device, data, data_len) != DAQ_SUCCESS) {
        pc->stats.hw_packets_dropped++;
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

static int pfring_daq_unload(void) {
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

static int pfring_daq_inject_relative(void *handle, const DAQ_Msg_t *msg, const uint8_t *data, uint32_t data_len, int reverse)
{
    PfringContext *pc = (PfringContext *)handle;
    PfringPktDesc *desc = (PfringPktDesc *)msg->priv;
    PfringDevice *source_device = &pc->devices[desc->pkthdr.ingress_index];
    PfringDevice *target_device;
    
    if (reverse) {
        target_device = source_device;
    } else if (desc->pkthdr.egress_index >= 0 && (uint32_t)desc->pkthdr.egress_index < pc->device_count) {
        target_device = &pc->devices[desc->pkthdr.egress_index];
    } else {
        return DAQ_ERROR;
    }

    if (pfring_transmit_packet(pc, target_device, data, data_len) != DAQ_SUCCESS) {
        pc->stats.hw_packets_dropped++;
        return DAQ_ERROR;
    }

    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const DAQ_ModuleAPI_t pfring_daq_module_data =
#endif
{
    .api_version = DAQ_MODULE_API_VERSION,
    .api_size = sizeof(DAQ_ModuleAPI_t),
    .module_version = DAQ_PFRING_VERSION,
    .name = "redborder_pfring",
    .type = DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    .load = pfring_daq_module_load,
    .interrupt = pfring_daq_interrupt,
    .unload = pfring_daq_unload,
    .get_variable_descs = pfring_daq_get_variable_descs,
    .instantiate = pfring_daq_instantiate,
    .destroy = pfring_daq_destroy,
    .start = pfring_daq_start,
    .stop = pfring_daq_stop,
    .set_filter = pfring_daq_set_filter,
    .ioctl = pfring_daq_ioctl,
    .get_stats = pfring_daq_get_stats,
    .reset_stats = pfring_daq_reset_stats,
    .get_snaplen = pfring_daq_get_snaplen,
    .get_capabilities = pfring_daq_get_capabilities,
    .get_datalink_type = pfring_daq_get_datalink_type,
    .config_load = NULL,
    .config_swap = NULL,
    .config_free = NULL,
    .inject = pfring_daq_inject,
    .inject_relative = pfring_daq_inject_relative,
    .msg_receive = pfring_daq_msg_receive,
    .msg_finalize = pfring_daq_msg_finalize,
    .get_msg_pool_info = pfring_daq_get_msg_pool_info,
};