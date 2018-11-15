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

#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "hvt.h"
#include "hvt_abi.h"
#include "hvt_kvm.h"
#include "hvt_cpu_x86_64.h"
#include "shm_net.h"
#include "writer.h"

int hvt_net_write(uint8_t nic_index, const uint8_t *buf, size_t len);
int hvt_net_read(uint8_t nic_index, uint8_t *buf, size_t len);
