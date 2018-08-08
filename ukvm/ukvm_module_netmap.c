/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of ukvm, a unikernel monitor.
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted, provided
 * that the above copyright notice and this permission notice appear
 * in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ukvm_module_netmap.c: Implements the hypercall layer to access dpdk api's
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <linux/kvm.h>

#include <net/netmap_user.h>

#include "ukvm.h"
#include "ukvm_guest.h"
#include "ukvm_hv_kvm.h"
#include "ukvm_cpu_x86_64.h"
#include "ukvm_module_net.h"

#ifdef __linux__
#define sockaddr_dl    sockaddr_ll
#define sdl_family     sll_family
#define AF_LINK        AF_PACKET
#define LLADDR(s)      s->sll_addr;
#endif

#define NUM_NETMAP_SLOTS 64
#define NUM_TX_SLOTS NUM_NETMAP_SLOTS
#define NUM_RX_SLOTS NUM_TX_SLOTS
#define NUM_TX_RINGS 1
#define NUM_RX_RINGS NUM_TX_RINGS

struct nm_data {
    struct nmreq nmreq;
    uint64_t nmd_flags;
    struct nm_desc *nmdesc;
};

/* For Netmap devices */
static struct nm_data *port;
static int nmd_fd;
static struct netmap_ring *txring, *rxring;
static uint32_t tx_buf_size, rx_buf_size;
static char *netiface;
static struct ukvm_netinfo netinfo;

static inline int need_next_slot(uint16_t flags)
{
    return (flags & NS_MOREFRAG);
}

static int handle_cmdarg(char *cmdarg)
{
    if (!strncmp("--netmap=", cmdarg, 9)) {
        netiface = cmdarg + 9;
        return 0;
    } else {
        return -1;
    }
}

#if 0
int netmap_write()
{
    int cur, ret = 0, read;
    char *buf;

    do {
        if (!nm_ring_space(txring)) {
            ret = -1;
            break;
        }

        cur = txring->cur;
        buf = NETMAP_BUF(txring, txring->slot[cur].buf_idx);
        if ((read = ukvm_net_read(0, (uint8_t *)buf, txring->nr_buf_size)) < 0) {
            break;
        }
        txring->slot[cur].len = read;
        txring->head = nm_ring_next(txring, cur);
    } while (1);

    if (ioctl(nmd_fd, NIOCTXSYNC, NULL) < 0) {
        ret = -1;
    }
    return ret;
}
#endif

int netmap_read(uint8_t **buf)
{
    struct  nm_pkthdr pkt;
    int ret = -1;

    *buf = nm_nextpkt(port->nmdesc, &pkt);
    if (*buf) {
        ret = pkt.len;
    }
    return ret;
}

void netmap_queue(int len)
{
    if (!nm_ring_space(txring)) {
        assert(0);
    }

    int cur = txring->cur;
    txring->slot[cur].len = len;
    txring->head = nm_ring_next(txring, cur);
}

void netmap_flush()
{
    if (ioctl(nmd_fd, NIOCTXSYNC, NULL) < 0) {
    }
}

uint8_t* netmap_buf()
{
    if (!nm_ring_space(txring)) {
        return NULL;
    }

    return (uint8_t*)NETMAP_BUF(txring, txring->slot[txring->cur].buf_idx);
}

int netmap_fd()
{ return nmd_fd; }

uint8_t* netmap_mac()
{
    return netinfo.mac_address;
}

/*
 * locate the src mac address for our interface, put it
 * into the user-supplied buffer. return 0 if ok, -1 on error.
 */
static int source_hwaddr(const char *ifname)
{
    struct ifaddrs *ifaphead, *ifap;

    if (getifaddrs(&ifaphead) != 0) {
        warnx("getifaddrs %s failed", ifname);
        return -1;
    }

    for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
        struct sockaddr_dl *sdl =
            (struct sockaddr_dl *)ifap->ifa_addr;
        uint8_t *mac;

        if (!sdl || sdl->sdl_family != AF_LINK)
            continue;
        if (strncmp(ifap->ifa_name, ifname, IFNAMSIZ) != 0)
            continue;
        mac = (uint8_t *)LLADDR(sdl);
        memcpy(netinfo.mac_address, mac, SOLO5_NET_ALEN); 
        warnx("mac address is %x\n", netinfo.mac_address[2]);
        break;
    }
    freeifaddrs(ifaphead);
    return ifap ? 0 : 1;
}

static int setup(struct ukvm_hv *hv)
{
    int i;
    char *ifname;

    txring = rxring = NULL;
    tx_buf_size = rx_buf_size = 0;

    if (netiface == NULL)
        return -1;

    printf("----- netmap module initialization -----\n");

    /* Obtain the MAC address */
    if (source_hwaddr(netiface) == -1) {
        err(1, "Could not get the MAC address: %s", netiface);
        return -1;
    }
    printf("Netmap port: MAC address(%s) on %s\n", netinfo.mac_address, netiface);

    /* Allocate the Netmap data */
    if ((port = calloc(1, sizeof(struct nm_data))) == NULL) {
        err(1, "Memory allocation error: port");
        return -1;
    }

    if ((ifname = malloc(sizeof(char) * (8 + strlen(netiface)))) == NULL) {
        err(1, "Memory allocation error: ifname");
        goto err_ifname;
    }
    snprintf(ifname, 8 + strlen(netiface), "netmap:%s", netiface);

    struct nmreq *base = &port->nmreq;
    base->nr_tx_slots = NUM_TX_SLOTS;
    base->nr_rx_slots = NUM_RX_SLOTS;
    base->nr_tx_rings = NUM_TX_RINGS;
    base->nr_rx_rings = NUM_RX_RINGS;

    /* TODO: how to deal with NETMAP_NO_TX_POLL */
    if ((port->nmdesc = nm_open(ifname, base, 0, NULL)) == NULL) {
        err(1, "Failed to open a Netmap port %s\n", ifname);
        goto err_open;
    }
    nmd_fd = port->nmdesc->fd;
    if (nmd_fd < 0) {
        err(1, "Something wrong in a flie descriptor.\n");
        goto err_open;
    };

    /* port information output */
    struct netmap_if *nifp = port->nmdesc->nifp;
    struct nmreq *req = &port->nmdesc->req;
    printf("mapped %dKB at %p\n", req->nr_memsize >> 10, port->nmdesc->mem);
    printf("# of TX queues: %d, # of RX queues: %d\n", req->nr_tx_rings, req->nr_rx_rings);
    printf("# of TX slots: %d, # of RX slots: %d\n", req->nr_tx_slots, req->nr_rx_slots);
    printf("Detail:\n");
    printf("    nifp at offset 0x%X\n", req->nr_offset);
    /* Just for ring checking */
    for(i = 0; i < req->nr_tx_rings; i++){
        struct netmap_ring *ring = NETMAP_TXRING(nifp, i);
        printf("    TX(%d) at %p / # of slots: %d\n", i, (void *)((char *)ring - (char *)nifp), ring->num_slots);
        if (ring->num_slots < NUM_TX_SLOTS) {
            err(1, "Shortage in the number of TX slots. it must be greater or equal to 64");
            goto err_config;
        }
    }
    for(i = 0; i < req->nr_rx_rings; i++){
        struct netmap_ring *ring = NETMAP_RXRING(nifp, i);
        printf("    RX(%d) at %p / # of slots: %d\n", i, (void *)((char *)ring - (char *)nifp), ring->num_slots);
        if (ring->num_slots < NUM_RX_SLOTS) {
            err(1, "Shortage in the number of TX slots. it must be greater or equal to 64");
            goto err_config;
        }
    }
    /* We use only the first ring pair */
    txring = NETMAP_TXRING(nifp, 0);
    rxring = NETMAP_RXRING(nifp, 0);
    tx_buf_size = txring->nr_buf_size;
    rx_buf_size = rxring->nr_buf_size;
    printf("    Slot buffer size: TX(%d)-%dBytes, RX(%d)-%dBytes\n", 0, tx_buf_size, 0, rx_buf_size);

    printf("----- netmap module initialization finished -----\n\n");
    return 0;

err_config:
    nm_close(port->nmdesc);
err_open:
    free(ifname);
err_ifname:
    free(port);
    return -1;
}

int nm_finalize(void)
{
    if (port) {
        if (port->nmdesc) {
            if (nm_close(port->nmdesc)) {
                err(1, "nm_close() failed");
                return -1;
            }
        }
        free(port);
    }

    return 0;
}

static char *usage(void)
{
    return "--netmap=DEVNAME (host network device which is \"Netmap-ready\")\n";
}

struct ukvm_module ukvm_module_netmap = {
    .name = "netmap",
    .setup = setup,
    .handle_cmdarg = handle_cmdarg,
    .usage = usage
};
