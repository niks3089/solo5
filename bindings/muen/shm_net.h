/*
 * Copyright (c) 2017 Contributors as noted in the AUTHORS file
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

#include "channel.h"
#include "reader.h"
#include "solo5.h"

#define PACKET_SIZE   1514
#define MUENNET_PROTO 0x7ade5c549b08e814ULL

struct net_msg {
    uint8_t data[PACKET_SIZE];
    uint16_t length;
} __attribute__((packed));

typedef enum {
    SHM_NET_OK = 0,
    SHM_NET_EPOCH_CHANGED,
    SHM_NET_XON,
    SHM_NET_AGAIN,
    SHM_NET_EINVAL
} shm_net_result_t;

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
        break;
    }
    return SOLO5_R_EUNSPEC;
}

shm_net_result_t shm_net_write(struct muchannel *channel,
        const uint8_t *buf, size_t size);
shm_net_result_t shm_net_read(struct muchannel *channel,
        struct muchannel_reader *reader,
        uint8_t *buf, size_t size, size_t *read_size);