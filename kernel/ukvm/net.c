/*
 * Copyright (c) 2015-2017 Contributors as noted in the AUTHORS file
 *
 * This file is part of Solo5, a unikernel base layer.
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

#include "kernel.h"
#include "shm_net.h"
#include "sinfo.h"
#include "reader.h"
#include "writer.h"

typedef struct {
    struct muchannel        *tx_channel;
    struct muchannel        *rx_channel;
    struct muchannel_reader net_rdr;
} muchannel_info;

static muchannel_info channel_info[100];

bool shm_poll_enabled  = false;
bool shm_event_enabled = false;

static inline solo5_result_t shm_to_solo5_result(int shm_result)
{
    switch(shm_result) {
    case SHM_NET_OK:
    case SHM_NET_XON:
        return SOLO5_R_OK;
    case SHM_NET_AGAIN:
    case SHM_NET_EPOCH_CHANGED:
        return SOLO5_R_AGAIN;
    default:
        return SOLO5_R_EUNSPEC;
    }
    return SOLO5_R_EUNSPEC;
}

solo5_result_t solo5_net_queue(int index, const uint8_t *buf, size_t size)
{
    int ret;

    assert(shm_event_enabled);
    ret = shm_net_write(channel_info[index].tx_channel, buf, size);
    return shm_to_solo5_result(ret);
}

void solo5_net_flush(int index)
{
    volatile struct ukvm_netindex ni;
    assert(shm_event_enabled);

    ni.index = index;
    ukvm_do_hypercall(UKVM_HYPERCALL_NETNOTIFY, &ni);

    assert(ni.ret == 0);
}

solo5_result_t solo5_net_write(int index, const uint8_t *buf, size_t size)
{
    int ret = 0;
    if (shm_event_enabled) {
        ret = solo5_net_queue(index, buf, size);
        solo5_net_flush(index);
        return ret;
    } else if (shm_poll_enabled) {
        ret = shm_net_write(channel_info[index].tx_channel, buf, size);
        return shm_to_solo5_result(ret);
    } else {
        volatile struct ukvm_netwrite wr;

        wr.index = index;
        wr.data = buf;
        wr.len = size;
        wr.ret = 0;

        ukvm_do_hypercall(UKVM_HYPERCALL_NETWRITE, &wr);

        return (wr.ret == 0 && wr.len == size) ? SOLO5_R_OK : SOLO5_R_EUNSPEC;
    }
}

solo5_result_t solo5_net_read(int index, uint8_t *buf, size_t size, size_t *read_size)
{
    int ret = 0;
    // Use index to retrieve rx_channel info
    if (shm_event_enabled) {
        ret = shm_net_read(channel_info[index].rx_channel,
                &(channel_info[index].net_rdr),
                buf, size, read_size);

        if (ret == SHM_NET_XON) {
            volatile struct ukvm_netindex ni;
            ni.index = index;
            ukvm_do_hypercall(UKVM_HYPERCALL_NETXON, &ni);
        }
        return shm_to_solo5_result(ret);
    } else if (shm_poll_enabled) {
       ret = shm_net_read(channel_info[index].rx_channel,
               &(channel_info[index].net_rdr),
               buf, size, read_size);
        return shm_to_solo5_result(ret);
    } else {
        volatile struct ukvm_netread rd;

        rd.index = index;
        rd.data = buf;
        rd.len = size;
        rd.ret = 0;

        ukvm_do_hypercall(UKVM_HYPERCALL_NETREAD, &rd);

        *read_size = rd.len;
        return (rd.ret == 0) ? SOLO5_R_OK : SOLO5_R_AGAIN;
    }
}

solo5_result_t solo5_net_info(int index, struct solo5_net_info *info)
{
    volatile struct ukvm_netinfo ni;

    ni.index = index;
    ukvm_do_hypercall(UKVM_HYPERCALL_NETINFO, &ni);

    if (ni.ret == 0) {
        memcpy(info->mac_address, (uint8_t *)&ni.mac_address,
                sizeof info->mac_address);
        /* XXX: No support on host side yet, so hardcode for now */
        info->mtu = 1500;
        return SOLO5_R_OK;
    }
    return SOLO5_R_EINVAL;
}

void net_init(void)
{
    volatile struct ukvm_net_shm_info ni = { 0 };
    ukvm_do_hypercall(UKVM_HYPERCALL_NET_SHMINFO, &ni);
    int xon_enabled = 0;
    int i;

    shm_poll_enabled = ni.shm_poll_enabled;
    shm_event_enabled = (xon_enabled = ni.shm_event_enabled);

    if (shm_poll_enabled || shm_event_enabled) {
        for (i = 0; i < ni.num_nics; i++) {
            channel_info[i].tx_channel =
                (struct muchannel *)ni.channel_info[i].tx_channel_addr;
            channel_info[i].rx_channel =
                (struct muchannel *)ni.channel_info[i].rx_channel_addr;

            muen_channel_init_writer(channel_info[i].tx_channel,
                    MUENNET_PROTO, sizeof(struct net_msg),
                    ni.tx_channel_addr_size, 10, xon_enabled);
            muen_channel_init_reader(&(channel_info[i].net_rdr), MUENNET_PROTO);
        }
    }
}
