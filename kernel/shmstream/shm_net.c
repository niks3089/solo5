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

#include "../kernel.h"
#include "sinfo.h"
#include "reader.h"
#include "writer.h"
#include "shm_net.h"

static struct muchannel *net_in;
static struct muchannel *net_out;
static struct muchannel_reader net_rdr;

int shm_net_write(uint8_t *data, int n)
{
    struct net_msg pkt;

    if (n > PACKET_SIZE)
        return -1;

    memset(&pkt, 0, sizeof(struct net_msg));
    cc_barrier();
    pkt.length = n;
    memcpy(&pkt.data, data, n);
    muen_channel_write(net_out, &pkt);

    return 0;
}

int shm_net_read(uint8_t *data, int *n)
{
    enum muchannel_reader_result result;
    struct net_msg pkt;
    int ret = -1;

    result = muen_channel_read(net_in, &net_rdr, &pkt);
    if (result == MUCHANNEL_SUCCESS) {
        memcpy(data, &pkt.data, sizeof(struct net_msg));
        *n = pkt.length;
        if (*n <= PACKET_SIZE)
            ret = 0;
    }

    return ret;
}

void shm_net_init()
{
    struct muen_channel_info channel;
    const uint64_t epoch = muen_get_sched_start();

    if (!muen_get_channel_info("net_out", &channel)) {
        //log(WARN, "Solo5: Net: No output channel\n");
        return;
    }
    net_out  = (struct muchannel *)(channel.address);
    muen_channel_init_writer(net_out, MUENNET_PROTO, sizeof(struct net_msg),
                             channel.size, epoch);
#if 0
    log(INFO, "Solo5: Net: Muen shared memory stream, protocol 0x%lx\n",
        MUENNET_PROTO);
    log(INFO, "Solo5: Net: Output channel @ 0x%lx, size 0x%lx, epoch 0x%lx\n",
        channel.address, channel.size, epoch);
#endif

    if (!muen_get_channel_info("net_in", &channel)) {
        //log(WARN, "Solo5: Net: No input channel\n");
        return;
    }
    net_in = (struct muchannel *)(channel.address);
    muen_channel_init_reader(&net_rdr, MUENNET_PROTO);
#if 0
    log(INFO, "Solo5: Net: Input  Channel @ 0x%lx, size 0x%lx\n", channel.address,
        channel.size);
#endif
}
