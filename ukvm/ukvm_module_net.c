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
 * ukvm_module_net.c: Network device module.
 */

#define _BSD_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "ukvm_module_net.h"

#if defined(__linux__)

/*
 * Linux TAP device specific.
 */
#define MAXEVENTS 5
static pthread_t tid;

#elif defined(__FreeBSD__)

#include <net/if.h>

#elif defined(__OpenBSD__)

#include <sys/socket.h>
#include <net/if.h>

#else /* !__linux__ && !__FreeBSD__ && !__OpenBSD__ */

#error Unsupported target

#endif

#include "ukvm.h"

#define MAX_PACKETS_READ 100
static char *num_nics_str;
static int num_nics;
static int epoll_fd;
static int use_shm_stream = 0;
static int use_event_thread = 0;
static uint64_t rx_shm_size = 0x250000;//1000 * ring_buf_size;
static uint64_t tx_shm_size = 0x250000;//1000 * ring_buf_size;
struct timespec readtime;
struct timespec writetime;
struct timespec epochtime;

#define FDS_PER_NIC 5
typedef struct {
    int                     index;
    int                     netfd;
    /* Eventfd to notify solo5 that pkt is ready to be read from shmstream */
    int                     solo5_rx_fd;
    /* Eventfd to notify solo5 that it its tx side is X'ONed and can start to queue packets */
    int                     solo5_tx_xon_evfd;
    int                     ukvm_rx_evfd;
    int                     ukvm_tx_xon_evfd;
    /* Tx channel addr can derived by adding the size of rx channel */
    uint64_t                rx_channel_guest_addr;
    struct muchannel        *rx_channel;
    struct muchannel        *tx_channel;
    struct muchannel_reader net_rdr;
    struct ukvm_netinfo     netinfo;
} ukvm_netinfo_table;

/* map between fds and the nic index it belongs to */
typedef struct {
    int    fd;
    int    index;
} ukvm_fd_index_map;

static ukvm_netinfo_table *netinfo_table;
static ukvm_fd_index_map  *fd_index_map;

int ukvm_net_write(uint8_t nic_index, const uint8_t *buf, size_t len)
{
    if (nic_index >= num_nics || !buf || !len) {
        return -1;
    }
    if (shm_net_write(netinfo_table[nic_index].tx_channel, buf,
          len) != SHM_NET_OK) {
      return -1;
    }
    return 0;
}

int ukvm_net_read(uint8_t nic_index, struct net_msg *pkt)
{
    if (nic_index >= num_nics || !pkt || !pkt->length) {
        return -1;
    }
    if (shm_net_read(netinfo_table[nic_index].rx_channel,
        &netinfo_table[0].net_rdr, pkt->data, PACKET_SIZE,
        (size_t *)&pkt->length) != SHM_NET_OK) {
        return -1;
    }
    return 0;
}


/*
 * Attach to an existing TAP interface named 'ifname'.
 *
 * Returns -1 and an appropriate errno on failure (ENOENT if the interface does
 * not exist), and the tap device file descriptor on success.
 */
static int tap_attach(const char *ifname)
{
    int fd;

    /*
     * Syntax @<number> indicates a pre-existing open fd, so just pass it
     * through without any checks.
     */
    if (ifname[0] == '@') {
        fd = atoi(&ifname[1]);

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
            return -1;

        return fd;
    }

    /*
     * Verify that the interface exists and is up and running. If we don't do
     * this then we get "create on open" behaviour on most systems which is not
     * what we want.
     */
    struct ifaddrs *ifa, *ifp;
    int found = 0;
    int up = 0;

    if (getifaddrs(&ifa) == -1)
        return -1;
    ifp = ifa;
    while (ifp) {
        if (strcmp(ifp->ifa_name, ifname) == 0) {
            found = 1;
            up = ifp->ifa_flags & (IFF_UP | IFF_RUNNING);
            break;
        }
        ifp = ifp->ifa_next;
    }
    freeifaddrs(ifa);
    if (!found) {
        errno = ENOENT;
        return -1;
    }

#if defined(__linux__)

    if (!up) {
        errno = ENETDOWN;
        return -1;
    }

    int err;
    struct ifreq ifr;

    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd == -1)
        return -1;

    /*
     * Initialise ifr for TAP interface.
     */
    memset(&ifr, 0, sizeof(ifr));
    /*
     * TODO: IFF_NO_PI may silently truncate packets on read().
     */
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (strlen(ifname) > IFNAMSIZ) {
        errno = EINVAL;
        return -1;
    }
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

    /*
     * Attach to the tap device; we have already verified that it exists, but
     * see below.
     */
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) == -1) {
        err = errno;
        close(fd);
        errno = err;
        return -1;
    }
    /*
     * If we got back a different device than the one requested, e.g. because
     * the caller mistakenly passed in '%d' (yes, that's really in the Linux
     * API) then fail.
     */
    if (strncmp(ifr.ifr_name, ifname, IFNAMSIZ) != 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

#elif defined(__FreeBSD__)

    char devname[strlen(ifname) + 6];

    snprintf(devname, sizeof devname, "/dev/%s", ifname);
    fd = open(devname, O_RDWR | O_NONBLOCK);
    if (fd == -1)
        return -1;

#elif defined(__OpenBSD__)

    if (!up) {
        errno = ENETDOWN;
        return -1;
    }

    char devname[strlen(ifname) + 6];

    snprintf(devname, sizeof devname, "/dev/%s", ifname);
    fd = open(devname, O_RDWR | O_NONBLOCK);
    if (fd == -1)
        return -1;
#endif

    return fd;
}

ukvm_fd_index_map *search_map_entry_from_fd(int fd)
{
  int i = 0;
  int total_entries = num_nics * FDS_PER_NIC;
  do {
      if (fd_index_map[i].fd == fd) {
          return &fd_index_map[i];
      }
  } while (++i < total_entries);
  return NULL;
}

ukvm_fd_index_map *add_index_to_map(int fd, int nic_index)
{
    static int next = 0;

    assert(next < FDS_PER_NIC * num_nics);

    warnx("Associating %d fd to %d NIC index\n", fd, nic_index);
    fd_index_map[next].fd = fd;
    fd_index_map[next].index = nic_index;
    return &fd_index_map[next++];
}

int netfd_notify_fn(void *data)
{
    ukvm_fd_index_map *map_entry = (ukvm_fd_index_map *)data;
    return map_entry->index;
}

/* Solo5 is woken up when the shmstream is writable again */
int read_solo5_tx_xon_fn(void *data)
{
    uint64_t clear = 0;
    ukvm_fd_index_map *map_entry = (ukvm_fd_index_map *)data;

    if (read(map_entry->fd, &clear, 8) < 0) {
        return -1;
    }
    return map_entry->index;
}

/* Solo5 is woken up when there is data to be read from
 * shmstream */
int read_solo5_rx_fn(void *data)
{
    uint64_t clear = 0;
    ukvm_fd_index_map *map_entry = (ukvm_fd_index_map *)data;

    /* Clears the notification */
    if (read(map_entry->fd, &clear, 8) < 0) {
        return -1;
    }
    return map_entry->index;
}

void* io_event_loop()
{
    struct net_msg pkt = { 0 };
    int ret, n, i, er, fd;
    uint64_t clear = 0, wrote = 1;
    struct epoll_event event;
    struct epoll_event *events;
    uint64_t packets_read = 0;
    ukvm_netinfo_table *entry = NULL;
    ukvm_fd_index_map  *map_entry = NULL;

    events = calloc(MAXEVENTS, sizeof event);

    while (1) {
        n = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++) {
            map_entry = events[i].data.ptr;
            entry = &netinfo_table[map_entry->index];
            fd    = map_entry->fd;
            if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN)))
            {
              warnx("epoll error\n");
              close(fd);
              continue;
            } else if (fd == entry->netfd) {
                packets_read = 0;
                while (packets_read < MAX_PACKETS_READ &&
                    ((ret = read(entry->netfd,
                        pkt.data, PACKET_SIZE)) > 0)) {
                    if (shm_net_write(entry->tx_channel,
                                pkt.data, ret) != SHM_NET_OK) {
                        /* Don't read from netfd. Instead, wait for tx_channel to
                         * be writable */
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL,
                                entry->netfd, NULL);
                        break;
                    }
                    packets_read++;
                }
                if (packets_read) {
                    ret = write(entry->solo5_rx_fd, &packets_read, 8);
                }
            } else if (fd == entry->ukvm_tx_xon_evfd) {
                /* tx channel is writable again */
                if ((er = read(entry->ukvm_tx_xon_evfd, &clear, 8))
                    != 8) {
                  assert(0);
                }

                /* Start reading from netfd */
                map_entry = search_map_entry_from_fd(entry->netfd);
                assert(map_entry);
                event.data.ptr = map_entry;
                event.events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, entry->netfd, &event);
            } else if (fd == entry->ukvm_rx_evfd) {
                /* Read data from shmstream and write to tap interface */
                do {
                    ret = shm_net_read(entry->rx_channel, &(entry->net_rdr),
                        pkt.data, PACKET_SIZE, (size_t *)&pkt.length);
                    if ((ret == SHM_NET_OK) || (ret == SHM_NET_XON)) {
                        if (ret == SHM_NET_XON) {
                            er = write(entry->solo5_tx_xon_evfd, &wrote, 8);
                        }
                        er = write(entry->netfd, pkt.data, pkt.length);
                        assert(er == pkt.length);
                    } else if (ret == SHM_NET_AGAIN) {
                        if (read(entry->ukvm_rx_evfd, &clear, 8) < 0) {}
                        break;
                    } else if (ret == SHM_NET_EPOCH_CHANGED) {
                        /* Don't clear the eventfd */
                        break;
                    } else {
                        assert(0);
                    }
                } while (1);
            }
		}
    }
}

void* io_thread()
{
    struct net_msg pkt;
    int ret, tap_no_data = 0, shm_no_data = 0;
    uint64_t packets_read = 0;

    while (1) {
        /* Read packets from tap interface and write to shmstream */
        while (packets_read < MAX_PACKETS_READ &&
            ((ret = read(netinfo_table[0].netfd, pkt.data, PACKET_SIZE)) > 0)) {
            packets_read++;
            if (shm_net_write(netinfo_table[0].tx_channel, pkt.data, ret) != SHM_NET_OK) {
                ret = 0;
                break;
            }
        }

        if ((ret == 0) ||
            (ret == -1 && errno == EAGAIN)) {
            /* NO data */
            tap_no_data = 1;
        } else if (ret < 0) {
            /* error */
            assert(0);
        }
        if (packets_read) {
            /* Notify the reader of shmstream */
            ret = write(netinfo_table[0].solo5_rx_fd, &packets_read, 8);
            packets_read = 0;
        }

        /* Read from shmstream and write to tap interface */
        while (packets_read < MAX_PACKETS_READ &&
            (ret = shm_net_read(netinfo_table[0].rx_channel,
                    &netinfo_table[0].net_rdr, pkt.data, PACKET_SIZE,
                    (size_t *)&pkt.length) == SHM_NET_OK)) {
            ret = write(netinfo_table[0].netfd, pkt.data, pkt.length);
            packets_read++;
            assert(ret == pkt.length);
        }

        if (ret == SHM_NET_AGAIN) {
            shm_no_data = 1;
        } else if (ret == SHM_NET_EINVAL) {
            warnx("Invalid error when read from shmstream");
            assert(0);
        }

        if (tap_no_data && shm_no_data) {
            /* Sleep for a millisec */
            usleep(1);
        }
        packets_read = 0;
        tap_no_data = 0;
        shm_no_data = 0;
    }
}

static void hypercall_net_shm_info(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    int i;
    struct ukvm_net_shm_info *info =
            UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_net_shm_info));

    /* Start the thread */
    if (use_shm_stream) {
        for (i = 0; i < num_nics; i++) {
            info->channel_info[i].tx_channel_addr =
                netinfo_table[i].rx_channel_guest_addr;
            info->channel_info[i].rx_channel_addr =
                netinfo_table[i].rx_channel_guest_addr + rx_shm_size;
        }
        info->num_nics = num_nics;
        info->tx_channel_addr_size = rx_shm_size;
        info->rx_channel_addr_size = tx_shm_size;
        if (use_event_thread) {
            info->shm_event_enabled = true;
        } else {
            info->shm_poll_enabled = true;
        }
    }
}

static void hypercall_netinfo(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netinfo *info =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netinfo));

    if (info->index >= num_nics) {
        info->ret = -1;
    }

    memcpy(info->mac_address, netinfo_table[info->index].netinfo.mac_address,
            SOLO5_NET_ALEN);
    info->ret = 0;
}

static void hypercall_netwrite(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netwrite *wr =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netwrite));
    int ret;

    assert (wr->index < num_nics);

    ret = write(netinfo_table[wr->index].netfd,
            UKVM_CHECKED_GPA_P(hv, wr->data, wr->len), wr->len);
    assert(wr->len == ret);
    wr->ret = 0;
}

static void hypercall_netread(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netread *rd =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netread));
    int ret;

    assert (rd->index < num_nics);

    ret = read(netinfo_table[rd->index].netfd,
            UKVM_CHECKED_GPA_P(hv, rd->data, rd->len), rd->len);
    if ((ret == 0) ||
        (ret == -1 && errno == EAGAIN)) {
        rd->ret = -1;
        return;
    }
    assert(ret > 0);
    rd->len = ret;
    rd->ret = 0;
}

static void hypercall_netxon(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netwrite *ni =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netindex));

    if (ni->index >= num_nics) {
        ni->ret = -1;
        return;
    }

    uint64_t xon = 1;
    if (write(netinfo_table[ni->index].ukvm_tx_xon_evfd, &xon, 8) != 8) {
        assert(0);
    } else {
        ni->ret = 0;
    }
}

/* Notify ukvm-bin that there is data to send */
static void hypercall_netnotify(struct ukvm_hv *hv, ukvm_gpa_t gpa)
{
    struct ukvm_netwrite *ni =
        UKVM_CHECKED_GPA_P(hv, gpa, sizeof (struct ukvm_netindex));

    if (ni->index >= num_nics) {
        ni->ret = -1;
        return;
    }

    uint64_t read_data = 1;
    if (write(netinfo_table[ni->index].ukvm_rx_evfd, &read_data, 8) != 8)
    {
        assert(0);
    }
    ni->ret = 0;
}

static int handle_cmdarg(char *cmdarg)
{
    if (!strncmp("--nic=", cmdarg, 6)) {
        num_nics_str = cmdarg + 6;
        return 0;
    } else if (!strncmp("--shm=poll", cmdarg, 10)) {
        use_shm_stream = 1;
        return 0;
    } else if (!strncmp("--shm=event", cmdarg, 11)) {
        use_shm_stream = 1;
        use_event_thread = 1;
        return 0;
    } else {
        return -1;
    }
}

static int configure_epoll(ukvm_netinfo_table *entry)
{
    struct epoll_event event;

    event.data.ptr = add_index_to_map(entry->netfd, entry->index);
    event.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, entry->netfd, &event) < 0) {
        warnx("Failed to set up fd at epoll_ctl");
        return -1;
    }

    if ((entry->ukvm_rx_evfd = eventfd(0, EFD_NONBLOCK)) < 0) {
        warnx("Failed to create eventfd for ukvm rx");
        return -1;
    }

    event.data.ptr = add_index_to_map(entry->ukvm_rx_evfd, entry->index);
    event.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, entry->ukvm_rx_evfd, &event) < 0) {
        warnx("Failed to set up fd at epoll_ctl for ukvm rx");
        return -1;
    }

    if ((entry->ukvm_tx_xon_evfd = eventfd(0, EFD_NONBLOCK)) < 0) {
        warnx("Failed to create eventfd for ukvm tx xon");
        return -1;
    }

    event.data.ptr = add_index_to_map(entry->ukvm_tx_xon_evfd, entry->index);
    event.events = EPOLLIN;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD,
          entry->ukvm_tx_xon_evfd, &event) < 0) {
        warnx("Failed to create eventfd for ukvm tx xon");
        return -1;
    }

    if ((entry->solo5_tx_xon_evfd = eventfd(0, EFD_NONBLOCK)) < 0) {
        warnx("Failed to create eventfd for solo5 tx xon");
        return -1;
    }

    return 0;
}

static int configure_shmstream_events(struct ukvm_hv *hv, ukvm_netinfo_table *entry)
{
    if (!entry) {
        return -1;
    }

    /* Set up eventfd */
    /* Why do we set it to sempahore?
     * We've 2 options. Consider a case where 10 packets are received
     * on a tap device and queued in shm. ukvm notifies solo5 via the
     * solo5_rx_fd and during this notification, the solo5_rx_fd is cleared.
     * The application will need to read to completion using solo5_read()
     * before going to yield since if it doesn't complete the reading, it will
     * not be notified again via yield. It could opt to pass 0 as timeout to
     * yield to finish reading but the application will need to keep track of it
     *
     * Setting it as semaphore will enforce the application to read once before
     * going back to yield to be woken up immediately. So if there are 10 packets
     * to be read, we will need to call yield and read 10 times which could be expensive.
     *
     * It depends on the application and this can set during initalisation or something.
     */
    entry->solo5_rx_fd = eventfd(0, EFD_NONBLOCK);// | EFD_SEMAPHORE);
    if (entry->solo5_rx_fd < 0) {
        err(1, "Failed to create eventfd");
        return -1;
    }

    if (use_event_thread) {
        /* Set up epoll */
        if ((configure_epoll(entry)) < 0) {
            err(1, "Failed to configure epoll");
            return -1;
        }
    }
    return 0;
}

static int configure_shmstream_mem(struct ukvm_hv *hv, ukvm_netinfo_table *entry,
        uint8_t *shm_mem)
{
    static uint64_t offset;
    int ret;

    /* RX ring buffer */
    struct kvm_userspace_memory_region rxring_region = {
        .slot = ukvm_mem_region++,
        .guest_phys_addr = hv->mem_size + (offset),
        .memory_size = (uint64_t)(rx_shm_size),
        .userspace_addr = (uint64_t)(shm_mem + offset),
    };
    ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &rxring_region);
    if (ret == -1) {
        err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: shmstream RX ring buffer");
        goto err;
    }
    entry->rx_channel_guest_addr = hv->mem_size + (offset);
    entry->rx_channel = (struct muchannel *)(shm_mem + offset);
    offset += rxring_region.memory_size;

    /* TX ring buffer */
    struct kvm_userspace_memory_region txring_region = {
        .slot = ukvm_mem_region++,
        .guest_phys_addr = hv->mem_size + (offset),
        .memory_size = (uint64_t)(tx_shm_size),
        .userspace_addr = (uint64_t)(shm_mem + offset),
    };
    ret = ioctl(hv->b->vmfd, KVM_SET_USER_MEMORY_REGION, &txring_region);
    if (ret == -1) {
        err(1, "KVM: ioctl (SET_USER_MEMORY_REGION) failed: shmstream TX ring buffer");
        goto err;
    }

    /* Init tx ring as a writer */
    entry->tx_channel = (struct muchannel *)(shm_mem + offset);
    /* TODO: Use monotonic epoch in kernel as well*/
    clock_gettime(CLOCK_MONOTONIC, &epochtime);
    muen_channel_init_writer(entry->tx_channel, MUENNET_PROTO, sizeof(struct net_msg),
            tx_shm_size, epochtime.tv_nsec, use_event_thread);
    offset += txring_region.memory_size;

    muen_channel_init_reader(&entry->net_rdr, MUENNET_PROTO);

    return 0;

err:
    return -1;
}

static int configure_nics(struct ukvm_hv *hv)
{
    char intf[8];
    int i, netfd, rfd, ret;
    uint8_t guest_mac[6];
    uint8_t *shm_mem = NULL;

    netinfo_table = (ukvm_netinfo_table *)calloc(1,
            num_nics * sizeof(ukvm_netinfo_table));

    if (!netinfo_table) {
        warnx("Failed to create netinfo table");
        return -1;
    }

    fd_index_map = (ukvm_fd_index_map *)calloc(1,
            num_nics * FDS_PER_NIC * sizeof(ukvm_fd_index_map));

    if (!fd_index_map) {
        warnx("Failed to create fd index map");
        return -1;
    }

    if (use_event_thread) {
        if ((epoll_fd = epoll_create1(0)) < 0) {
            warnx("Failed to create epoll fd");
            return -1;
        }
    }

    if (use_shm_stream) {
        uint64_t total_shm_buf_size = (rx_shm_size + tx_shm_size) * num_nics;
        uint64_t total_pagesize = 0x0;

        if ((hv->mem_size + total_shm_buf_size) > (X86_GUEST_PAGE_SIZE * 512)) {
            err(1, "guest memory size exceeds the max size %u bytes", X86_GUEST_PAGE_SIZE * 512);
            return -1;
        }

        shm_mem = mmap(NULL, total_shm_buf_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (shm_mem == MAP_FAILED) {
            err(1, "Failed allocate memory for shmstream");
            return -1;
        }

        do {
            total_pagesize += X86_GUEST_PAGE_SIZE;
        } while(total_pagesize < total_shm_buf_size);

        warnx("total_pagesize = 0x%"PRIx64"\n",total_pagesize);
        ukvm_x86_add_pagetables(hv->mem, hv->mem_size, total_pagesize);
    }

    for (i = 0; i < num_nics; i++) {

        /* If the backend is tap */
        snprintf(intf, sizeof intf, "tap%d", i + 100);
        warnx("Creating interface %s\n", intf);
        netfd = tap_attach(intf);
        if (netfd < 0) {
            err(1, "Could not attach interface: %s", intf);
            exit(1);
        }
        netinfo_table[i].index = i;
        netinfo_table[i].netfd = netfd;

        rfd = open("/dev/urandom", O_RDONLY);

        if (rfd == -1)
            err(1, "Could not open /dev/urandom");

        ret = read(rfd, guest_mac, sizeof(guest_mac));
        assert(ret == sizeof(guest_mac));
        close(rfd);
        guest_mac[0] &= 0xfe;
        guest_mac[0] |= 0x02;
        memcpy(netinfo_table[i].netinfo.mac_address, guest_mac, SOLO5_NET_ALEN);

        /* If the backend is netmap */
        /* If the backend is dpdk */

        if (use_shm_stream) {
            int flags = fcntl(netinfo_table[i].netfd, F_GETFL, 0);
            fcntl(netinfo_table[i].netfd, F_SETFL, flags | O_NONBLOCK);

            if (configure_shmstream_events(hv, &netinfo_table[i])) {
                err(1, "Failed to configure shmstream events");
                exit(1);
            }

            if (configure_shmstream_mem(hv, &netinfo_table[i], shm_mem)) {
                err(1, "Failed to configure shmstream memory");
                exit(1);
            }

            assert(ukvm_core_register_pollfd(netinfo_table[i].solo5_rx_fd,
                    read_solo5_rx_fn,
                    add_index_to_map(netinfo_table[i].solo5_rx_fd, i)) == 0);
            if (use_event_thread) {
                assert(ukvm_core_register_pollfd(netinfo_table[i].solo5_tx_xon_evfd,
                        read_solo5_tx_xon_fn,
                        add_index_to_map(netinfo_table[i].solo5_tx_xon_evfd, i)) == 0);
            }
        } else {
            assert(ukvm_core_register_pollfd(netinfo_table[i].netfd,
                    netfd_notify_fn,
                    add_index_to_map(netinfo_table[i].netfd, i)) == 0);
        }
    }

    if (use_shm_stream) {
        if (use_event_thread) {
            if (pthread_create(&tid, NULL, &io_event_loop, NULL) != 0) {
                warnx("Failed to create event thread");
                return -1;
            }
        } else {
            if (pthread_create(&tid, NULL, &io_thread, NULL) != 0) {
                warnx("Failed to create polling thread");
                return -1;
            }
        }
    }
    return 0;
}

static int setup(struct ukvm_hv *hv)
{
    if (num_nics_str == NULL)
        return -1;

    num_nics = strtoumax(num_nics_str, NULL, 10);

    warnx("nic:number of nics is %d\n", num_nics);

    if (num_nics == UINTMAX_MAX && errno == ERANGE) {
        warnx("Invalid nic number\n");
        return -1;
    } else if (num_nics >= 10) {
        warnx("Invalid nic range\n");
        return -1;
    }
    if (configure_nics(hv) < 0) {
        warnx("Failed to configure nics\n");
        return -1;
    }

    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETINFO,
                hypercall_netinfo) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETWRITE,
                hypercall_netwrite) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETREAD,
                hypercall_netread) == 0);
    assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NET_SHMINFO,
                hypercall_net_shm_info) == 0);
    if (use_event_thread) {
        assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETXON,
                    hypercall_netxon) == 0);
        assert(ukvm_core_register_hypercall(UKVM_HYPERCALL_NETNOTIFY,
                    hypercall_netnotify) == 0);
    }

    return 0;
}

static char *usage(void)
{
    return "--nic=number of NICs \n"
           " --shm=poll for shared memory polling\n"
           " --shm=event for shared memory event-driven\n";
}

static void cleanup(struct ukvm_hv *hv)
{
    if (use_shm_stream) {
        if (pthread_cancel(tid) == 0) {
            pthread_join(tid, NULL);
        }
    }
}

struct ukvm_module ukvm_module_net = {
    .name = "net",
    .setup = setup,
    .handle_cmdarg = handle_cmdarg,
    .usage = usage,
    .cleanup = cleanup
};
