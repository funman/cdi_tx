/*
 * Copyright (C) 2012-2015 OpenHeadend S.A.R.L.
 * Copyright (C) 2022 Open Broadcast Systems Ltd
 *
 * Authors: Christophe Massiot
 *          Benjamin Cohen
 *          Rafaël Carré
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The following comes from libfabric v1.9.1-42-g617566eab util/pingpong.c
 *
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos Nat. Security, LLC. All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 * Copyright (c) 2021 Open Broadcast Systems Ltd.
 *
 * This software is available to you under the BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

#include <sys/mman.h>

#include <rdma/fi_cm.h>

#include "util.h"

static int fd;
static struct sockaddr_in dst;

static int max_msg_size;
static uint16_t src_port;
static uint16_t dst_port;
static char *dst_addr;

static int transfer_size;

static struct fi_info *fi;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static struct fid_ep *ep;
static struct fid_cq *rxcq;
static struct fid_mr *mr;
static struct fid_av *av;

static void *buf, *rx_buf;
static size_t x_size;
static size_t buf_size;


static uint8_t state;

static uint16_t ctrl_packet_num;
static uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
static char senders_ip_str[MAX_IP_STRING_LENGTH+1];

static ProbeState probe_state;
static uint16_t pkt_num;
static char ip[INET6_ADDRSTRLEN];

static size_t width;
static size_t height;

static size_t rxidx;

static const char *get_cmd(ProbeCommand cmd)
{
    static const char *foo[] = {
        [kProbeCommandReset] = "Reset",
        [kProbeCommandPing] = "Ping",
        [kProbeCommandConnected] = "Connected",
        [kProbeCommandAck] = "Ack",
        [kProbeCommandProtocolVersion] = "ProtocolVersion",
    };

    if (cmd < kProbeCommandReset || cmd > kProbeCommandProtocolVersion)
        return "?";

    return foo[cmd];
}

static void fisrc_parse_cmd(const uint8_t *buf, size_t n, ProbeCommand *command)
{
    const uint8_t *orig_buf = buf;
    assert(n > 100);

    uint8_t v     = buf[0]; ///< CDI protocol version number.
    uint8_t major = buf[1]; ///< CDI protocol major version number.
    uint8_t probe = buf[2]; ///< CDI probe version number.

    buf += 3;
    n -= 3;

    *command = get_32le(buf);
    buf += 4;
    n -= 4;

    memcpy(senders_ip_str, buf, MAX_IP_STRING_LENGTH);
    senders_ip_str[MAX_IP_STRING_LENGTH] = '\0';
    buf += MAX_IP_STRING_LENGTH;
    n -= MAX_IP_STRING_LENGTH;

    inet_aton(senders_ip_str, &dst.sin_addr);

    memcpy(senders_gid_array, buf, MAX_IPV6_GID_LENGTH);
    buf += MAX_IPV6_GID_LENGTH;
    n -= MAX_IPV6_GID_LENGTH;

    char senders_stream_name_str[CDI_MAX_STREAM_NAME_STRING_LENGTH+1];
    memcpy(senders_stream_name_str, buf, sizeof(senders_stream_name_str));
    senders_stream_name_str[CDI_MAX_STREAM_NAME_STRING_LENGTH] = '\0';
    buf += CDI_MAX_STREAM_NAME_STRING_LENGTH;
    n -= CDI_MAX_STREAM_NAME_STRING_LENGTH;

    if (v == 1) {
        // senders_stream_identifier
        buf += 4; // 32 bits
        n -= 4;
    }

    uint16_t senders_control_dest_port = get_16le(buf);
    buf += 2;
    n -= 2;

    dst.sin_port = htons(senders_control_dest_port);

    pkt_num = get_16le(buf);
    buf += 2;
    n -= 2;

    const uint8_t *csum_pos = buf;
    uint16_t csum = get_16le(buf);
    buf += 2;
    n -= 2;

    if (*command == kProbeCommandAck) {
        uint8_t ack_command = get_32le(buf);
        buf += 4;
        n -= 4;
        uint16_t ack_control_packet_num = get_16le(buf);
        buf += 2;
        n -= 2;

        fprintf(stderr, "ack cmd: %d - num %d\n", ack_command, ack_control_packet_num);
    } else {
        bool requires_ack = buf[0];
        (void)requires_ack;
        buf += 1;
        n -= 1;
    }

    uint16_t checksum = CalculateChecksum(orig_buf, buf - orig_buf, csum_pos);
    if (csum != checksum) {
        fprintf(stderr, "bad checksum 0x%.4x != 0x%.4x\n", csum, checksum);
    }

    fprintf(stderr, "#%hu v%u.%u.%u %s:%hu \"%s\" %s\n",
            pkt_num, v, major, probe,
            senders_ip_str, senders_control_dest_port, senders_stream_name_str,
            get_cmd(*command)
        );
}

static int get_cq_comp(struct fid_cq *cq)
{
    struct fi_cq_data_entry comp[50];

    int ret = fi_cq_read (cq, comp, 1);
    if (ret > 0) {
    } else if (ret == -FI_EAGAIN) {
            return -1;
    } else if (ret == -FI_EAVAIL) {
        struct fi_cq_err_entry cq_err = { 0 };

        int ret = fi_cq_readerr (cq, &cq_err, 0);
        if (ret < 0) {
            fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr\n", ret, fi_strerror(-ret));
            return ret;
        }

        fprintf(stderr, "X %s\n", fi_cq_strerror (cq, cq_err.prov_errno,
                    cq_err.err_data, NULL, 0));
        return -cq_err.err;
    } else if (ret < 0) {
        fprintf(stderr, "%s(): ret=%d (%s)\n", "get_cq_comp\n", ret, fi_strerror(-ret));
        return ret;
    }

    return 0;
}

static ssize_t rx (void)
{
    if (get_cq_comp (rxcq)) {
        return -1;
    }

    uint64_t n = 1;//8;

    struct iovec msg_iov[8];
    for (int i = 0; i < n; i++) {
        msg_iov[i].iov_base = (uint8_t*)rx_buf + ((rxidx+i)%376) * UBUF_DEFAULT_SIZE_A;
        msg_iov[i].iov_len = UBUF_DEFAULT_SIZE;
    };

    assert(n <= sizeof(msg_iov)/sizeof(*msg_iov));

    struct fi_msg msg = {
        .msg_iov = msg_iov,
        .desc = fi_mr_desc (mr),
        .iov_count = n,
        .addr = 0,
        .context = NULL,
        .data = 0,
    };

    ssize_t s = fi_recvmsg(ep, &msg, FI_COMPLETION);
    if (s)
        fprintf(stderr, "fi_recvmsg");

    return n;
}

static int alloc_msgs (void)
{
    const unsigned int size_max_power_two = 22;
    const size_t max_msg_size = fi->ep_attr->max_msg_size;
    static const unsigned int packet_buffer_alignment = 8;
    static const unsigned int packet_size = UBUF_DEFAULT_SIZE;
    static const unsigned int packet_count = 376;

    const int aligned_packet_size = (packet_size + packet_buffer_alignment - 1) & ~(packet_buffer_alignment - 1);
    assert(aligned_packet_size == UBUF_DEFAULT_SIZE_A);
    int allocated_size = aligned_packet_size * packet_count;

    x_size = (1 << size_max_power_two) + (1 << (size_max_power_two - 1));
    x_size = allocated_size;

    if (x_size > max_msg_size)
        x_size = max_msg_size;

    size_t buf_size = x_size;

    assert(x_size >= transfer_size);

    errno = 0;
    long alignment = sysconf (_SC_PAGESIZE);
    if (alignment <= 0)
        return 1;

    #define CDI_HUGE_PAGES_BYTE_SIZE    (2 * 1024 * 1024)
    buf_size += CDI_HUGE_PAGES_BYTE_SIZE;
    buf_size &= ~(CDI_HUGE_PAGES_BYTE_SIZE-1);

    buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (buf == MAP_FAILED) {
        RET(posix_memalign (&buf, (size_t) alignment, buf_size));
    }

    memset (buf, 0, buf_size);
    rx_buf = buf;

    RET(fi_mr_reg (domain, buf, buf_size,
            FI_RECV, 0, 0, 0, &mr, NULL));

    return 0;
}

static void fisrc_alloc(void)
{
    max_msg_size = 0;

    max_msg_size = transfer_size = UBUF_DEFAULT_SIZE;
    ctrl_packet_num = 0;

    struct fi_info *hints = fi_allocinfo();
    if (!hints) {
    }

    hints->caps = FI_MSG;
    hints->mode = FI_CONTEXT;
    hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED /*| FI_MR_PROV_KEY */| FI_MR_VIRT_ADDR;

    hints->fabric_attr->prov_name = (char*)"sockets";
    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->rx_attr->comp_order = FI_ORDER_NONE;
    hints->tx_attr->comp_order = FI_ORDER_NONE;

    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            NULL, NULL, FI_SOURCE /* ? */, hints, &fi));

    assert(fi);

    RET(fi_fabric (fi->fabric_attr, &fabric, NULL));
    RET(fi_domain (fabric, fi, &domain, NULL));
    struct fi_cq_attr cq_attr = {
        .wait_obj = FI_WAIT_NONE,
        .format = FI_CQ_FORMAT_DATA,
        .size = fi->rx_attr->size,
    };

    RET(fi_cq_open (domain, &cq_attr, &rxcq, &rxcq));

    struct fi_av_attr av_attr = {
        .type = FI_AV_TABLE,
        .count = 1
    };

    RET(fi_av_open (domain, &av_attr, &av, NULL));

    RET(fi_endpoint (domain, fi, &ep, NULL));

    RET(fi_ep_bind(ep, &av->fid, 0));
    RET(fi_ep_bind(ep, &rxcq->fid, FI_RECV));

    RET(fi_enable (ep));
    RET(alloc_msgs ());

    dst.sin_family = AF_INET;

    probe_state = kProbeStateIdle;
    pkt_num = 0;
    ip[0] = '\0';
    width = 0;
    height = 0;

    hints->fabric_attr->prov_name = NULL; // Value is statically allocated, so don't want libfabric to free it.
    fi_freeinfo (hints);
}

static void transmit(ProbeCommand cmd, bool requires_ack, ProbeCommand reply)
{
    uint8_t tx_buf[300];
    memset(tx_buf, 0, sizeof(tx_buf));
    uint8_t *buf = tx_buf;

    // senders_version
    *buf++ = 2;
    *buf++ = 2;
    *buf++ = 5;

    // ProbeCommand
    put_32le(buf, cmd);
    buf += 4;

    // senders_ip_str
    strncpy((char*)buf, ip, MAX_IP_STRING_LENGTH - 1);
    buf[MAX_IP_STRING_LENGTH - 1] = '\0';

    buf += MAX_IP_STRING_LENGTH;

    // senders_gid_array
    uint8_t ipv6_gid[MAX_IPV6_GID_LENGTH];

    size_t name_length = MAX_IPV6_GID_LENGTH;

    int ret = fi_getname(&ep->fid, (void*)ipv6_gid, &name_length);
    if (ret) {
        fprintf(stderr, "CRAP");
    } else {
        memset(buf, 0, MAX_IPV6_GID_LENGTH);
        memcpy(buf, ipv6_gid, name_length);
    }

    buf += MAX_IPV6_GID_LENGTH;

    // senders_stream_name_str
    buf += CDI_MAX_STREAM_NAME_STRING_LENGTH;

    // senders_control_dest_port
    uint16_t port = 47593; // TODO
    put_16le(buf, port);
    buf += 2;

    // control_packet_num
    put_16le(buf, ctrl_packet_num++);
    buf += 2;

    // checksum
    uint8_t *csum = buf; /* written later */
    put_16le(buf, 0);
    buf += 2;

    if (cmd == kProbeCommandAck) {
        // ack_command
        put_32le(buf, reply);
        buf += 4;

        // ack_control_packet_num
        put_16le(buf, pkt_num);
        buf += 2;
    } else {
        // requires_ack
        *buf++ = !!requires_ack;
    }

    size_t n = buf - tx_buf;

    uint16_t checksum = CalculateChecksum(tx_buf, n, NULL);

    put_16le(csum, checksum);
    ssize_t ss = sendto(fd, tx_buf, n, 0, (struct sockaddr*)&dst, sizeof(dst));
    if (ss < 0)
        perror("sendto");
}

static const char *get_pt(int pt)
{
    static const char *foo[] = {
        [kPayloadTypeData] = "Data",
        [kPayloadTypeDataOffset] = "DataOffset",
        [kPayloadTypeProbe] = "Probe",
        [kPayloadTypeKeepAlive] = "KeepAlive",
    };

    if (pt < kPayloadTypeData || pt > kPayloadTypeKeepAlive)
        return "?";

    return foo[pt];
}

static void fisrc_worker2(void)
{
    uint64_t systime = now();

    ssize_t pkts = 1;
    uint8_t *b= NULL;

//    printf("%s()\n", __func__);

    for (;;) {

    if (--pkts <= 0) {
        pkts = rx();
//        printf("rx=%zd\n", pkts);
        if (pkts < 0)
            return;
        printf("rxidx %zu\n", rxidx);
        b = rx_buf + (rxidx % 376) * UBUF_DEFAULT_SIZE_A;
        rxidx += pkts;
    } else {
        b += UBUF_DEFAULT_SIZE_A;
        if (b == rx_buf + 376 * UBUF_DEFAULT_SIZE_A)
            b = rx_buf;
    }
    uint8_t *buffer = b;
    ssize_t s = UBUF_DEFAULT_SIZE;
    size_t offset = 0;

    assert(s >= 9);
    assert(s == UBUF_DEFAULT_SIZE);

    uint8_t pt = buffer[0];
    uint16_t seq = get_16le(&buffer[1]);
    uint16_t num = get_16le(&buffer[3]);
    uint32_t id = get_32le(&buffer[5]);
//    if (pt != kPayloadTypeDataOffset && pt != kPayloadTypeProbe /*&& pt != kPayloadTypeData */)
//        fprintf(stderr, "PT %s(%d) - seq %d num %d id %d\n", get_pt(pt), pt, seq, num, id);
    static int prev_id;
    if (id != prev_id + 1)
        printf("\terr\n");
    printf("id %d\n", id);
    prev_id = id;

    buffer += 9;
    s -= 9;

    //assert(buffer[-9] == pt);

    switch(pt) {
    case kPayloadTypeData:
        if (seq == 0) {
            assert(s >= 4+8+8+8+2+8);
            uint32_t total_payload_size = get_32le(buffer); buffer += 4;
            uint64_t max_latency_microsecs = get_64le(buffer); buffer += 8;
            uint32_t sec = get_32le(buffer); buffer += 4; /// The number of seconds since the SMPTE Epoch which is 1970-01-01T00:00:00.
            uint32_t nsec = get_32le(buffer); buffer += 4; /// The number of fractional seconds as measured in nanoseconds. The value in this field is always less than 10^9.
            // TODO : pts

            uint64_t payload_user_data = get_64le(buffer); buffer += 8;

            uint16_t  extra_data_size = get_16le(buffer); buffer += 2;

            uint64_t tx_start_time_microseconds = get_64le(buffer); buffer += 8;
            // TODO : mesure network latency?

            fprintf(stderr,
                    "total payload size %u max latency usecs %" PRId64 " PTP %u.%09u userdata %" PRIx64 " extradata %d tx_start_time_usec %" PRId64 "\n",

                    total_payload_size,
                    max_latency_microsecs,
                    sec,
                    nsec,
                    payload_user_data,
                    extra_data_size,
                    tx_start_time_microseconds);

            s -= 4+8+8+8+2+8;
            //assert(buffer[-47] == pt);

            //parse_cdi_extra(uref_mgr->udict_mgr, buffer, extra_data_size);
            if (extra_data_size > s)
                extra_data_size = s;
            s -= extra_data_size;
            buffer += extra_data_size;
        }
        break;

    case kPayloadTypeDataOffset:
        assert(s >= 4);
        offset = get_32le(buffer);
        buffer += 4; s -= 4;
        break;
    case kPayloadTypeKeepAlive:
        break;
    case kPayloadTypeProbe:
        if (probe_state == kProbeStateEfaProbe) {
            /* Don't wait for an arbitrary number of packets (EFA_PROBE_PACKET_COUNT) */
            probe_state = kProbeStateEfaTxProbeAcks;
            transmit(kProbeCommandConnected, false, 0);
        }

        s = 0;
    default: break;
    }

    {
//    fprintf(stderr, "%s(offset=%zu) at %.6f\n", __func__, offset, ((float)systime) / 27000000.);
        static uint64_t start;
        if (offset == 0)
            start = systime;
        if (offset + s > 5184000) {
            fprintf(stderr, "got pic after %.6f ms\n", ((float)(systime - start)) / 27000.);
        }
    }

    static bool go = false;
    if (offset == 0)
        go = true;
    if (!go)
        return;

    bool uref_new = false;

    uint16_t *y, *u, *v;

    if (uref_new) {
        //{ 0xF0, 0x0A, 0x46, 0xE0, 0xA4 }, // Blue
        uint8_t a = 0xf0, b = 0x0a, c = 0x46, d = 0xe0, e = 0xa4;
        uint16_t u1 = (a << 2)          | ((b >> 6) & 0x03); //1111111122
        uint16_t y1 = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
        uint16_t v1 = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
        uint16_t y2 = ((d & 0x03) << 8) | e;                 //4455555555
        for (int i = 0; i < 1920*1080/2; i++) {
            u[i] = u1;
            v[i] = v1;
            y[2*i] = y1;
            y[2*i+1] = y2;
        }
    }

    static uint8_t x[5184000];
    if (offset + s > 5184000)
        s = 5184000 - offset;
    memcpy(&x[offset], buffer, s);

    if (0 && offset + s == 5184000) {
        const uint8_t *src = x;
        for (int i = 0; i < 1920*1080; i += 2) {
            uint8_t a = *src++;
            uint8_t b = *src++;
            uint8_t c = *src++;
            uint8_t d = *src++;
            uint8_t e = *src++;
            u[i/2] = (a << 2)          | ((b >> 6) & 0x03); //1111111122
            y[i+0] = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
            v[i/2] = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
            y[i+1] = ((d & 0x03) << 8) | e;                 //4455555555
         }
    }

    if (offset + s >= 5184000) {
        printf("PIC\n");
    }
    }
}

static void protocol(void)
{
    uint8_t buffer[1500];

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t ret = recvfrom(fd, buffer, sizeof(buffer),
           0, (struct sockaddr*)&addr, &addrlen);

    if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        struct sockaddr_in *s = (struct sockaddr_in*)&addr;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6*)&addr;
        void *src = addr.ss_family == AF_INET ? (void*)&s->sin_addr : (void*)&s6->sin6_addr;
        if (inet_ntop(addr.ss_family, src, ip, sizeof(ip)))
            ip[0] = '\0';
    }

    if (unlikely(ret == -1)) {
        switch (errno) {
            case EINTR:
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                /* not an issue, try again later */
                return;
            case EBADF:
            case EINVAL:
            case EIO:
            default:
                break;
        }
        fprintf(stderr, "read error (%m)");
        return;
    }

    if (unlikely(ret == 0)) {
        return;
    }

    ProbeCommand cmd;
    fisrc_parse_cmd(buffer, ret, &cmd);

    transmit(kProbeCommandAck, false, cmd);
    if (cmd == kProbeCommandProtocolVersion)
        probe_state = kProbeStateEfaProbe;
    if (cmd == kProbeCommandPing) {
        probe_state = kProbeStateEfaConnected;
        printf("\tCONNECTED\n\n");
    }
}

static void fisrc_free(void)
{
    fi_close(&mr->fid);
    fi_close(&ep->fid);
    fi_close(&rxcq->fid);
    fi_close(&av->fid);
    fi_close(&domain->fid);
    fi_close(&fabric->fid);

    munmap(buf, buf_size);

    fi_freeinfo (fi);
}

int main (void)
{
    src_port = FI_DEFAULT_PORT+1;
    dst_port = FI_DEFAULT_PORT;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = INADDR_ANY,
        .sin_port = htons(src_port),
    };

    if (bind(fd, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("bind");
        return 2;
    }

    fisrc_alloc();

    /* post all RX buffers */
    for (int i = 0; i < 376; i += 1) {
        struct iovec msg_iov[8];
        for (int j = 0; j < 1; j++) {
            msg_iov[j].iov_base = (uint8_t*)rx_buf + (i+j) * UBUF_DEFAULT_SIZE_A;
            msg_iov[j].iov_len = UBUF_DEFAULT_SIZE;
        };

        struct fi_msg msg = {
            .msg_iov = msg_iov,
            .desc = fi_mr_desc (mr),
            .iov_count = 1,
            .addr = 0,
            .context = NULL,
            .data = 0,
        };

        uint64_t flags = 0;
        if (i < 376 - 1)
            flags |= FI_MORE;
        ssize_t s = fi_recvmsg(ep, &msg, flags);
        if (s) {
            fprintf(stderr, "fi_recvmsg\n");
        }
    }

    for (;;) {
        struct pollfd pfd[1] = {
            {
                .fd = fd,
                .events = POLLIN,
            },
        };
        nfds_t n = sizeof(pfd) / sizeof(*pfd);

        int ret = poll(pfd, n, 0 /* ms */);
        switch (ret) {
            case 0: // timeout
                if (probe_state == kProbeStateEfaConnected)
                    fisrc_worker2();
                continue;
            default:
                break;
            case -1:
                perror("poll");
                goto end;
        }

        for (int i = 0; i < n; i++) {
            if (pfd[0].revents) {
                protocol();
            }
        }
    }

end:
    fisrc_free();
    close(fd);

    return 0;
}
