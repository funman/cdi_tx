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

/** default size of buffers when unspecified */
#define UBUF_DEFAULT_SIZE      8961
#define UBUF_DEFAULT_SIZE_A    8968

#define FI_DEFAULT_PORT 47592
#define CTRL_PORT 1234


#define MAX_IP_STRING_LENGTH                (64)

/// @brief Maximum EFA device GID length. Contains GID + QPN (see efa_ep_addr).
#define MAX_IPV6_GID_LENGTH                 (32)

/// @brief Maximum IPV6 address string length.
#define MAX_IPV6_ADDRESS_STRING_LENGTH      (64)

/// @brief Maximum connection name string length.
#define CDI_MAX_CONNECTION_NAME_STRING_LENGTH           (128)

/// @brief Maximum stream name string length.
#define CDI_MAX_STREAM_NAME_STRING_LENGTH               (CDI_MAX_CONNECTION_NAME_STRING_LENGTH+10)

#define unlikely(x)     __builtin_expect(!!(x),0)

#define RET(cmd)        \
do {                    \
    int ret = cmd;      \
    if (unlikely(ret)) {\
        printf("%s():%d : ret=%d\n", __func__, __LINE__, ret); \
    }                   \
} while (0)


static char *src;
static char *dst;
static char *port;
/** udp socket descriptor */
static int fd;

////
static int max_msg_size;
static uint16_t src_port;
static uint16_t dst_port;
static char *dst_addr;

static int transfer_size;

static struct fi_info *fi;
static struct fid_fabric *fabric;
static struct fid_domain *domain;
static struct fid_ep *ep;
static struct fid_cq *txcq;
static struct fid_mr *mr;
static struct fid_av *av;

static uint64_t tx_seq, tx_cq_cntr;

static void *buf, *tx_buf;
static size_t x_size;

static uint8_t state;

static uint16_t ctrl_packet_num;
static uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
static char senders_ip_str[MAX_IP_STRING_LENGTH+1];

static struct uref *output_uref;

static uint16_t pkt_num;
static char ip[INET6_ADDRSTRLEN];

static size_t width;
static size_t height;

static size_t buf_size;

static fi_addr_t remote_fi_addr;

typedef enum {
    kProbeCommandReset = 1, ///< Request to reset the connection. Start with 1 so no commands have the value 0.
    kProbeCommandPing,      ///< Request to ping the connection.
    kProbeCommandConnected, ///< Notification that connection has been established (probe has completed).
    kProbeCommandAck,       ///< Packet is an ACK response to a previously sent command.
    kProbeCommandProtocolVersion, ///< Packet contains protocol version of sender.
} ProbeCommand;

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

static void put_32le(uint8_t *buf, const uint32_t val)
{
    for (int i = 0; i < 4; i++)
        buf[i] = (val >> 8*i) & 0xff;
}

static uint32_t get_32le(const uint8_t *buf)
{
    uint32_t val = 0;
    for (int i = 0; i < 4; i++)
        val |= buf[i] << i*8;
    return val;
}

static uint64_t get_64le(const uint8_t *buf)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
        val |= buf[i] << i*8;
    return val;
}

static void put_16le(uint8_t *buf, const uint16_t val)
{
    *buf++ = val & 0xff;
    *buf++ = val >> 8;
}

static uint16_t get_16le(const uint8_t *buf)
{
    uint16_t val = *buf++;
    val |= *buf << 8;
    return val;
}

typedef enum {
    kPayloadTypeData = 0,   ///< Payload contains application payload data.
    kPayloadTypeDataOffset, ///< Payload contains application payload data with data offset field in each packet.
    kPayloadTypeProbe,      ///< Payload contains probe data.
    kPayloadTypeKeepAlive,  ///< Payload is being used for keeping the connection alive (don't use app payload
                            ///  callbacks).
} CdiPayloadType;

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

static int get_cq_comp(struct fid_cq *cq, uint64_t *cur, uint64_t total)
{
    struct fi_cq_data_entry comp;

    int z = 0;
    do {
        int ret = fi_cq_read (cq, &comp, 1);
        if (ret > 0) {
            if (ret != 1)
                printf("cq_read %d\n", ret);
            (*cur)++;
        } else if (ret == -FI_EAGAIN) {
            if (z++ > 10)
                return 1;
            continue;
        } else if (ret == -FI_EAVAIL) {
            (*cur)++;
            struct fi_cq_err_entry cq_err = { 0 };

            int ret = fi_cq_readerr (cq, &cq_err, 0);
            if (ret < 0) {
                fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr", ret, fi_strerror(-ret));
                return ret;
            }

            fprintf(stderr, "X %s\n", fi_cq_strerror (cq, cq_err.prov_errno,
                        cq_err.err_data, NULL, 0));
            exit(1);
            return -cq_err.err;
        } else if (ret < 0) {
            fprintf(stderr, "%s(): ret=%d (%s)\n", "get_cq_comp", ret, fi_strerror(-ret));
            return ret;
        }
    } while (total - *cur > 0);

    return 0;
}

static ssize_t tx(void)
{
    if (get_cq_comp (txcq, &tx_cq_cntr, tx_seq))
        return -1;

    uint64_t n = tx_cq_cntr % 3000;

    struct iovec msg_iov = {
        .iov_base = (uint8_t*)tx_buf + n * UBUF_DEFAULT_SIZE_A,
        .iov_len = UBUF_DEFAULT_SIZE,
    };
//    struct fi_context ctx[2];

    struct fi_msg msg = {
        .msg_iov = &msg_iov,
        .desc = fi_mr_desc (mr),
        .iov_count = 1,
        .addr = 0,
        .context = NULL, //ctx,
        .data = 0,
    };

    printf(".\n");
    ssize_t s = fi_sendmsg(ep, &msg, FI_TRANSMIT_COMPLETE);
    if (!s)
        tx_seq++;
    else {
        fprintf(stderr, "fi_sendmsg\n");
    }

    return msg_iov.iov_len;
}

static uint16_t CalculateChecksum(const uint8_t *buf, int size, const uint8_t *csum_pos)
{
    uint32_t cksum = 0;

    // Sum entire packet.
    while (size > 1) {
        uint16_t word = get_16le(buf);
        if (csum_pos) { /* zero checksum when verifying */
            if (csum_pos == buf+1)
                word &= 0x00ff;
            else if (csum_pos == buf-1)
                word &= 0xff00;
            else if (csum_pos == buf) /* should not happen */ {
                word = 0;
                abort();
            }
        }
        cksum += word;
        buf += 2;
        size -= 2;
    }

    // Pad to 16-bit boundary if necessary.
    if (size == 1) {
        cksum += *buf;
    }

    // Add carries and do one's complement.
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16_t)(~cksum);
}

static int alloc_msgs (void)
{
    const unsigned int size_max_power_two = 22;
    const size_t max_msg_size = fi->ep_attr->max_msg_size;
    static const unsigned int packet_buffer_alignment = 8;
    static const unsigned int packet_size = UBUF_DEFAULT_SIZE;
    static const unsigned int packet_count = 3000;

    const int aligned_packet_size = (packet_size + packet_buffer_alignment - 1) & ~(packet_buffer_alignment - 1);
    assert(aligned_packet_size == UBUF_DEFAULT_SIZE_A);
    int allocated_size = aligned_packet_size * packet_count;

    x_size = (1 << size_max_power_two) + (1 << (size_max_power_two - 1));
    x_size = allocated_size;

    if (x_size > max_msg_size)
        x_size = max_msg_size;

    buf_size = x_size;

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
    tx_buf = buf;

    RET(fi_mr_reg (domain, buf, buf_size,
            FI_RECV, 0, 0, 0, &mr, NULL));

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

//    free (buf); // FIXME
    munmap(buf, buf_size);

    fi_freeinfo (fi);
}

static void tx_alloc(void)
{
    tx_seq = 0;
    tx_cq_cntr = 0;
    output_uref = NULL;

    max_msg_size = 0;

    src_port = FI_DEFAULT_PORT+1;
    dst_port = FI_DEFAULT_PORT;

    max_msg_size = transfer_size = UBUF_DEFAULT_SIZE;
    ctrl_packet_num = 0;

    struct fi_info *hints = fi_allocinfo();
    if (!hints) {
    }

    hints->caps = FI_MSG;
    hints->mode = FI_CONTEXT;
    hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED | /*FI_MR_PROV_KEY | */FI_MR_VIRT_ADDR;

    hints->fabric_attr->prov_name = (char*)"sockets";
    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->tx_attr->comp_order = FI_ORDER_NONE;

    char *node = dst;
    char service[12];
    snprintf(service, sizeof(service), "%d", atoi(port) + 1);
    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            node, service, 0/* ? */, hints, &fi));

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

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s src dst:port\n", argv[0]);
        return 1;
    }

    src = argv[1];
    dst = argv[2];
    port = strchr(dst, ':');
    if (!port) {
        fprintf(stderr, "Invalid port\n");
        return 2;
    }

    *port++ = '\0';

    int p = atoi(port);

    struct in_addr a_dst;
    if (!inet_aton(dst, &a_dst)) {
        fprintf(stderr, "Invalid IP %s\n", dst);
        return 3;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
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
        .sin_port = htons(CTRL_PORT),
    };

    if (bind(s, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("bind");
        return 6;
    }

    addr.sin_port = htons(p);
    addr.sin_addr = a_dst;
    if (connect(s, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("connect");
        return 7;
    }

    tx_alloc();

    printf("GO\n");

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
    pkt.v = 2;
    pkt.major = 1;
    pkt.minor = 4;
    strcpy(pkt.senders_ip_str, src);
    pkt.senders_gid_array[0] = '\0';
    strcpy(pkt.senders_stream_name_str, "foobar");
    pkt.senders_control_dest_port = CTRL_PORT;
    pkt.control_packet_num = 0;

    ssize_t ret;

    pkt.command = kProbeCommandReset;
    pkt.control_packet_num++;
    pkt.checksum = 0;
    pkt.checksum = CalculateChecksum((uint8_t*)&pkt, sizeof(pkt) - 3, (uint8_t*)&pkt.checksum);

    ret = send(s, &pkt, sizeof(pkt), 0);
    if (ret < 0)
        perror("send");
    usleep(10000);

    pkt.command = kProbeCommandProtocolVersion;
    pkt.checksum = 0;
    pkt.control_packet_num++;
    pkt.checksum = CalculateChecksum((uint8_t*)&pkt, sizeof(pkt) - 3, (uint8_t*)&pkt.checksum);
    ret = send(s, &pkt, sizeof(pkt), 0);
    if (ret < 0)
        perror("send");
    usleep(10000);

    pkt.command = kProbeCommandPing;
    pkt.checksum = 0;
    pkt.checksum = CalculateChecksum((uint8_t*)&pkt, sizeof(pkt) - 3, (uint8_t*)&pkt.checksum);
    ret = send(s, &pkt, sizeof(pkt), 0);
    if (ret < 0)
        perror("send");
    usleep(10000);


    ret = recv(s, &pkt, sizeof(pkt), 0);
    if (ret < 0) {
        perror("recv");
        return 7;
    }

    int count = 1;
    uint64_t flags = 0;
    void* context_ptr = NULL;
    static fi_addr_t remote_fi_addr;

    int fi_ret = fi_av_insert(av, (void*)&pkt.senders_gid_array, count,
            &remote_fi_addr, flags, context_ptr);
    if (count != fi_ret) {
        // This is a fatal error.
        fprintf(stderr, "Failed to start Tx connection. fi_av_insert() failed[%d (%s)]\n",
                fi_ret, fi_strerror(-fi_ret));
    }

    /* */

    uint64_t n = tx_cq_cntr % 3000;
    uint8_t *data_pkt = tx_buf + n * UBUF_DEFAULT_SIZE_A;
    memset(data_pkt, 0, UBUF_DEFAULT_SIZE);

    data_pkt[0] = kPayloadTypeProbe;
    uint16_t seq = 0, num = 0;
    uint32_t id = 0;
    put_16le(&data_pkt[1], seq);
    put_16le(&data_pkt[3], num);
    put_32le(&data_pkt[5], id);

    tx();

    for (;;) {
        //kPayloadTypeData = 0,   ///< Payload contains application payload data.
        //x * kPayloadTypeDataOffset, ///< Payload contains application payload data with data offset field in each
        break;
    }

end:
    tx_free();
    return 0;
}
