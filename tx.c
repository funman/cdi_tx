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

#include <sys/mman.h>

#include <rdma/fi_cm.h>

#include "util.h"

static uint16_t width = 1920;
static uint16_t height = 1080;
static uint16_t fps_num = 25;
static uint16_t fps_den = 1;
static bool interlaced = true;
static size_t pic_size;
static uint64_t pic_duration;

static unsigned int packet_count;

static char *src;
static char *dst;
static int fd;
static int sock;

static uint8_t pic[1920*1080*5/2]; /* 40 bits per 2 pixels (UYVY) */
static uint32_t offset = 0;
static uint16_t seq = 0;   // seqnum in pic
static uint16_t num = 0;   // pic num
static uint32_t id = 0;    // pkt num


static int ctrl_port = 1234;
static char *dst_addr;

static struct fi_info *fi;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static struct fid_ep *ep;
static struct fid_cq *txcq;
static struct fid_mr *mr;
static struct fid_av *av;

static uint64_t rx_idx; // currently written to
static uint64_t tx_idx; // actually transmitted

static void *tx_buf;

static uint8_t state;

static uint16_t ctrl_packet_num;
static uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
static char senders_ip_str[MAX_IP_STRING_LENGTH+1];

static struct uref *output_uref;

static uint16_t pkt_num;
static char ip[INET6_ADDRSTRLEN];

static size_t buf_size;
static bool use_free;

static fi_addr_t remote_fi_addr;

static int get_cq_comp(void)
{
    struct fi_cq_data_entry comp[50];

    int ret = fi_cq_read (txcq, comp, sizeof(comp) / sizeof(*comp));
    if (ret > 0) {
        tx_idx += ret;
//        printf("%d ", ret); fflush(stdout);
    } else switch (ret) {
        case -FI_EAGAIN: break;
        case 0: break;
        case -FI_EAVAIL:
                struct fi_cq_err_entry cq_err = { 0 };

                ret = fi_cq_readerr (txcq, &cq_err, 0);
                if (ret < 0) {
                    fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr", ret, fi_strerror(-ret));
                    return ret;
                }

                fprintf(stderr, "X %s\n", fi_cq_strerror (txcq, cq_err.prov_errno,
                            cq_err.err_data, NULL, 0));
                return -cq_err.err;
        default:
                fprintf(stderr, "%s(): ret=%d (%s)\n", "get_cq_comp", ret, fi_strerror(-ret));
                exit(1);
                return ret;
    }

    static uint64_t last;
    static uint64_t last_idx;
    uint64_t t = now();
    if (t - last > 1000000000) {
        float bps = 8. * (tx_idx - last_idx) * UBUF_DEFAULT_SIZE;
        bps /= 1024 * 1024.;
        printf("busy %" PRId64 , rx_idx - tx_idx);
        printf(" tx_idx got + %" PRId64 " (%.2f Mbps)\n", tx_idx - last_idx, bps);
        last_idx = tx_idx;
        last = t;
    }

    return 0;
}

static void tx(void)
{
    struct iovec msg_iov = {
        .iov_base = (uint8_t*)tx_buf + (rx_idx++ % packet_count) * UBUF_DEFAULT_SIZE_A,
        .iov_len = UBUF_DEFAULT_SIZE,
    };
    void *descs = fi_mr_desc(mr);

    struct fi_msg msg = {
        .msg_iov = &msg_iov,
        .desc = &descs,
        .iov_count = 1,
        .addr = 0,
        .context = NULL,
        .data = 0,
    };

    uint64_t flags = 0;
    ssize_t s = fi_sendmsg(ep, &msg, flags);

    if (s) {
        fprintf(stderr, "fi_sendmsg (idx %" PRIu64 ") : %s\n", rx_idx, fi_strerror(-s));
        abort();
    }
}

static int alloc_msgs (void)
{
    static const unsigned int packet_buffer_alignment = 8;
    static const unsigned int packet_size = UBUF_DEFAULT_SIZE;
    fi->ep_attr->max_msg_size = packet_size;

    const int aligned_packet_size = (packet_size + packet_buffer_alignment - 1) & ~(packet_buffer_alignment - 1);
    assert(aligned_packet_size == UBUF_DEFAULT_SIZE_A);
    buf_size = aligned_packet_size * packet_count;

    long alignment = sysconf (_SC_PAGESIZE);
    if (alignment <= 0)
        return 1;

    #define CDI_HUGE_PAGES_BYTE_SIZE    (2 * 1024 * 1024)
    buf_size += CDI_HUGE_PAGES_BYTE_SIZE;
    buf_size &= ~(CDI_HUGE_PAGES_BYTE_SIZE-1);
    printf("buf size %zu\n", buf_size);

    tx_buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (tx_buf == MAP_FAILED) {
        RET(posix_memalign (&tx_buf, (size_t) alignment, buf_size));
        use_free = true;
    }

    memset (tx_buf, 0, buf_size);

    RET(fi_mr_reg (domain, tx_buf, buf_size,
            FI_SEND, 0, 0, 0, &mr, NULL));

    return 0;
}

static void tx_free(void)
{
    fi_close(&mr->fid);
    fi_close(&ep->fid);
    fi_close(&txcq->fid);
    fi_close(&av->fid);
    fi_close(&domain->fid);
    fi_close(&fabric->fid);

    if (use_free)
        free (tx_buf);
    else
        munmap(tx_buf, buf_size);

    fi_freeinfo (fi);
}

static void tx_alloc(int port)
{
    rx_idx = 0;
    tx_idx = 0;
    output_uref = NULL;

    ctrl_packet_num = 0;

    struct fi_info *hints = fi_allocinfo();
    if (!hints) {
    }

    hints->caps = FI_MSG;
    hints->mode = FI_CONTEXT;
    hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED | /*FI_MR_PROV_KEY | */FI_MR_VIRT_ADDR;

    bool efa = is_efa();

    hints->fabric_attr->prov_name = efa ? (char*)"efa" : (char*)"sockets";
    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->tx_attr->comp_order = FI_ORDER_NONE;
    hints->rx_attr->comp_order = FI_ORDER_NONE;

    char *node = dst;
    char service[12];
    snprintf(service, sizeof(service), "%d", port);
    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
                efa ? NULL : node, efa ? NULL : service,
                0/* ? */, hints, &fi));

    RET(fi_fabric (fi->fabric_attr, &fabric, NULL));
    RET(fi_domain (fabric, fi, &domain, NULL));
    struct fi_cq_attr cq_attr = {
        .wait_obj = FI_WAIT_NONE,
        .format = FI_CQ_FORMAT_DATA,
        .size = fi->tx_attr->size,
    };

    RET(fi_cq_open (domain, &cq_attr, &txcq, &txcq));

    struct fi_av_attr av_attr = {
        .type = FI_AV_TABLE,
        .count = 1
    };

    RET(fi_av_open (domain, &av_attr, &av, NULL));

    RET(fi_endpoint (domain, fi, &ep, NULL));

    RET(fi_ep_bind(ep, &av->fid, 0));
    RET(fi_ep_bind(ep, &txcq->fid, FI_TRANSMIT));

    RET(fi_enable (ep));
    RET(alloc_msgs());

    hints->fabric_attr->prov_name = NULL; // Value is statically allocated, so don't want libfabric to free it.
    fi_freeinfo (hints);
}

static int conn(void)
{
    /*
        -> reset
        <- ack
        -> protocolversion
        <- ack
        <- connected
            -> ping
            <- ack
    */

    // connection
    struct __attribute__((__packed__)) {
        uint8_t v;
        uint8_t major;
        uint8_t minor;
        ProbeCommand command;
        char senders_ip_str[MAX_IP_STRING_LENGTH];
        uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
        char senders_stream_name_str[CDI_MAX_STREAM_NAME_STRING_LENGTH];
        uint16_t senders_control_dest_port;
        uint16_t control_packet_num;
        uint16_t checksum;
        bool requires_ack;
    } pkt;

    memset(&pkt, 0, sizeof(pkt));

    pkt.v = 2;
    pkt.major = 1;
    pkt.minor = 4;

    strcpy(pkt.senders_ip_str, src);
    pkt.senders_gid_array[0] = '\0';
    strcpy(pkt.senders_stream_name_str, "foobar");
    pkt.senders_control_dest_port = ctrl_port;

    ProbeCommand cmd[3] = {
        kProbeCommandReset,
        kProbeCommandProtocolVersion,
        kProbeCommandPing,
    };

    for (int i = 0; i < 3; i++) {
        pkt.command = cmd[i];
        pkt.control_packet_num = i;
        pkt.checksum = 0;
        pkt.checksum = CalculateChecksum((uint8_t*)&pkt, sizeof(pkt) - 3, (uint8_t*)&pkt.checksum);

        if (send(sock, &pkt, sizeof(pkt), 0) < 0) {
            perror("send");
            return 1;
        }
        usleep(10000);
    }

    if (recv(sock, &pkt, sizeof(pkt), 0) < 0) {
        perror("recv");
        return 1;
    }

    int fi_ret = fi_av_insert(av, (void*)&pkt.senders_gid_array, 1,
            &remote_fi_addr, 0, NULL);
    if (1 != fi_ret) {
        fprintf(stderr, "fi_av_insert: %s\n", fi_strerror(-fi_ret));
        return 8;
    }

    return 0;
}

static void data_pkt(unsigned int idx)
{
    uint8_t *pkt_buf = tx_buf + ((rx_idx + idx) % packet_count) * UBUF_DEFAULT_SIZE_A;
    bool is_offset = seq != 0;
    size_t s = UBUF_DEFAULT_SIZE;

    *pkt_buf++ = is_offset ? kPayloadTypeDataOffset : kPayloadTypeData; s--;
    put_16le(pkt_buf, seq); pkt_buf += 2; s -= 2;
    put_16le(pkt_buf, num); pkt_buf += 2; s -= 2;
    put_32le(pkt_buf, id++); pkt_buf += 4; s -= 4;

    if (is_offset) {
        put_32le(pkt_buf, offset); pkt_buf += 4; s -= 4;
    } else {
        uint32_t total_payload_size = width * height * 5 / 2;
        uint64_t max_latency_usec = UINT64_C(1000000) * fps_den / fps_num;;
        uint32_t sec = 0;
        uint32_t nsec = 0;
        uint64_t payload_user_data = 0;
        uint64_t tx_start_time_usec = 0;
        uint16_t extra_data_size = 1290;

        put_32le(pkt_buf, total_payload_size); pkt_buf += 4; s -= 4;
        put_64le(pkt_buf, max_latency_usec); pkt_buf += 8; s -= 8;
        put_32le(pkt_buf, sec); pkt_buf += 4; s -= 4;
        put_32le(pkt_buf, nsec); pkt_buf += 4; s -= 4;
        put_64le(pkt_buf, payload_user_data); pkt_buf += 8; s -= 8;
        put_16le(pkt_buf, extra_data_size); pkt_buf += 2; s -= 2;
        put_64le(pkt_buf, tx_start_time_usec); pkt_buf += 8; s -= 8;

        assert(s >= extra_data_size);
        assert(extra_data_size == 2 + 257 + 1024 + 3 + 4);

        uint16_t stream_id = 0;
        put_16le(pkt_buf, stream_id); pkt_buf += 2; s -= 2;
        snprintf(pkt_buf, 257, "https://cdi.elemental.com/specs/baseline-video");
        pkt_buf += 257; s -= 257;       // uri
        uint32_t data_size = snprintf(pkt_buf, 1024, "cdi_profile_version=01.00; sampling=YCbCr422; depth=10;%s width=%hu; height=%hu; exactframerate=%u/%u; colorimetry=BT709; RANGE=Full;",
            interlaced ? " interlace;" : "", width, height, fps_num, fps_den);
        pkt_buf += 1024; s -= 1024;     // data
        pkt_buf += 3; s -= 3;           // packing
        put_32le(pkt_buf, data_size); pkt_buf += 4; s -= 4;
    }

    s -= (s%5); // round to pixel boundary
    if (offset + s > pic_size)
        s = pic_size - offset;

    memcpy(pkt_buf, &pic[offset], s);

    offset += s;

    if (++seq == packet_count) {
        assert(offset == pic_size);
        num++;
        seq = 0;
        offset = 0;
    }
}

static void data(void)
{
    if (get_cq_comp())
        fprintf(stderr, "get_cq_comp failed\n");

    unsigned int avail = packet_count - (rx_idx - tx_idx);
    if (avail > packet_count - seq)
        avail = packet_count - seq;

    for (unsigned int i = 0; i < avail; i++)
        data_pkt(i);

    for (unsigned int i = 0; i < avail; i++)
        tx();
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s src dst:port\n", argv[0]);
        return 1;
    }

    src = argv[1];
    dst = argv[2];

    pic_size = width * height * 5 / 2;
    const size_t total_pic_size = pic_size + 1290 /* extra data */ + 36 /* packet #0 */;
    size_t packet_size = 8864 /* ? */ - 9 /* seq/num header */ - 4 /* offset */;
    packet_size -= (packet_size % 5);
    packet_count = (total_pic_size + packet_size - 1) / packet_size;
    pic_duration = UINT64_C(1000000) * fps_den / fps_num;;

    char *p = strchr(dst, ':');
    if (!p) {
        fprintf(stderr, "Invalid port\n");
        return 2;
    }

    *p++ = '\0';
    int port = atoi(p);

    struct in_addr a_dst;
    if (!inet_aton(dst, &a_dst)) {
        fprintf(stderr, "Invalid IP %s\n", dst);
        return 3;
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 4;
    }
    struct in_addr a_src;
    if (!inet_aton(src, &a_src)) {
        fprintf(stderr, "Invalid IP %s\n", src);
        return 5;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr = a_src,
        .sin_port = htons(ctrl_port),
    };

    for (;;) {
        unsigned int seed = ctrl_port;
        if (bind(sock, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
            perror("bind");
            usleep(100000);
            ctrl_port = rand_r(&seed) & 0xffff;
            if (ctrl_port < 1024)
                ctrl_port += 1024;
            printf("ctrl port %u\n", ctrl_port);
            addr.sin_port = htons(ctrl_port);
            continue;
        } else
            break;
    }

    addr.sin_port = htons(port);
    addr.sin_addr = a_dst;
    if (connect(sock, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("connect");
        return 7;
    }

    tx_alloc(port);

    if (conn())
        return 8;

    // PROBE

    for (int i = 0; i < packet_count; i++) {
        uint8_t *d= tx_buf + (i % packet_count) * UBUF_DEFAULT_SIZE_A;
        d[0] = kPayloadTypeProbe;
        put_16le(&d[1], seq++);
        put_16le(&d[3], num);
        put_32le(&d[5], id++);
        tx();
    }

    seq = id = 0;

    uint64_t t = now();
    for (;;) {
        if (seq == 0) {
            if (fread(pic, pic_size, 1, stdin) != 1) {
                perror("fread");
                goto end;
            }
            uint64_t prev = t;
            t = now();
            if (prev) {
                prev = (t - prev) / 1000;
                if (prev < pic_duration) {
                    prev = pic_duration - prev;
                    usleep(prev);
                    printf("sleeping %" PRIu64 " us\n", prev);
                }
            }
        }
        data();
    }

end:
    tx_free();
    return 0;
}
