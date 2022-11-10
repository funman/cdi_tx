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

typedef enum {
    kProbeStateIdle, // Waiting for ProtocolVersion
    kProbeStateEfaProbe, // Got ProtocolVersion, waiting for probe packets through EFA
    kProbeStateEfaTxProbeAcks, // Received probe packets, sends Connected
    kProbeStateEfaConnected, // Connected
} ProbeState;


/** udp socket descriptor */
static int fd;
/* */
static struct sockaddr_in dst;

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
static struct fid_cq *rxcq;
static struct fid_mr *mr;
static struct fid_av *av;

static uint64_t rx_seq, rx_cq_cntr;

static void *buf, *rx_buf;
static size_t x_size;

static uint8_t state;

static uint16_t ctrl_packet_num;
static uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
static char senders_ip_str[MAX_IP_STRING_LENGTH+1];

static struct uref *output_uref;

static ProbeState probe_state;
static uint16_t pkt_num;
static char ip[INET6_ADDRSTRLEN];

static size_t width;
static size_t height;

static size_t buf_size;

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

static ssize_t rx(void)
{
    if (get_cq_comp (rxcq, &rx_cq_cntr, rx_seq))
        return -1;

    uint64_t n = rx_cq_cntr % 3000;

    struct iovec msg_iov = {
        .iov_base = (uint8_t*)rx_buf + n * UBUF_DEFAULT_SIZE_A,
        .iov_len = UBUF_DEFAULT_SIZE,
    };

    struct fi_msg msg = {
        .msg_iov = &msg_iov,
        .desc = fi_mr_desc (mr),
        .iov_count = 1,
        .addr = 0,
        .context = NULL,
        .data = 0,
    };

    ssize_t s = fi_recvmsg(ep, &msg, FI_RECV);
    if (!s)
        rx_seq++;
    else {
        fprintf(stderr, "fi_recvmsg\n");
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

static void transmit(ProbeCommand cmd, bool requires_ack, ProbeCommand reply)
{
    uint8_t tx_buf[300];
    memset(tx_buf, 0, sizeof(tx_buf));
    uint8_t *buf = tx_buf;

    // senders_version
    *buf++ = 2;
    *buf++ = 1;
    *buf++ = 4;

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
        fprintf(stderr, "CRAP\n");
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

static void tx_worker2(void)
{
    for (;;) {
    uint64_t n = rx_cq_cntr % 3000;
    uint8_t *buffer = rx_buf + n * UBUF_DEFAULT_SIZE_A;
    ssize_t s = rx();

    size_t offset = 0;
    if (s <= 0)
        return;

    assert(s >= 9);
    assert(s == UBUF_DEFAULT_SIZE);

    uint8_t pt = buffer[0];
    uint16_t seq = get_16le(&buffer[1]);
    uint16_t num = get_16le(&buffer[3]);
    uint32_t id = get_32le(&buffer[5]);
    if (pt != kPayloadTypeDataOffset && pt != kPayloadTypeProbe && pt != kPayloadTypeData)
        fprintf(stderr, "PT %s(%d) - seq %d num %d id %d\n", get_pt(pt), pt, seq, num, id);

    buffer += 9;
    s -= 9;

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

            //parse_cdi_extra(buffer, extra_data_size);
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

    static bool go = false;
    if (offset == 0)
        go = true;
    if (!go)
        return;

    static uint8_t x[5184000];
    if (offset + s > 5184000)
        s = 5184000 - offset;
    memcpy(&x[offset], buffer, s);

    if (offset + s == 5184000) {
        const uint8_t *src = x;
        for (int i = 0; i < 1920*1080; i += 2) {
            uint8_t a = *src++;
            uint8_t b = *src++;
            uint8_t c = *src++;
            uint8_t d = *src++;
            uint8_t e = *src++;
            //u[i/2] = (a << 2)          | ((b >> 6) & 0x03); //1111111122
            //y[i+0] = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
            //v[i/2] = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
            //y[i+1] = ((d & 0x03) << 8) | e;                 //4455555555
         }
    }

    if (offset + s >= 5184000) {
        output_uref = NULL;
        // out
    }
    }
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
    rx_buf = buf;

    RET(fi_mr_reg (domain, buf, buf_size,
            FI_RECV, 0, 0, 0, &mr, NULL));

    return 0;
}

static void tx_free(void)
{
    fi_close(&mr->fid);
    fi_close(&ep->fid);
    fi_close(&rxcq->fid);
    fi_close(&av->fid);
    fi_close(&domain->fid);
    fi_close(&fabric->fid);

//    free (buf); // FIXME
    munmap(buf, buf_size);

    fi_freeinfo (fi);
}

static void tx_alloc(void)
{
    rx_seq = 0;
    rx_cq_cntr = 0;
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
        FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;

    hints->fabric_attr->prov_name = (char*)"sockets";
    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->rx_attr->comp_order = FI_ORDER_NONE;

    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            NULL, NULL, FI_SOURCE /* ? */, hints, &fi));

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
    RET(alloc_msgs());

    fd = -1;
    dst.sin_family = AF_INET;

    probe_state = kProbeStateIdle;
    pkt_num = 0;
    ip[0] = '\0';
    width = 0;
    height = 0;

    hints->fabric_attr->prov_name = NULL; // Value is statically allocated, so don't want libfabric to free it.
    fi_freeinfo (hints);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s src dst:port\n", argv[0]);
        return 1;
    }

    char *src = argv[1];
    char *dst = argv[2];
    char *port = strchr(dst, ':');
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
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(p),
        .sin_addr = a_dst,
    };

    if (connect(s, (struct sockaddr*)&addr, (socklen_t)sizeof(addr)) < 0) {
        perror("connect");
        return 5;
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
    pkt.senders_control_dest_port = 1234;
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

    for (;;) {
        // data
        break;
    }

end:
    tx_free();
    return 0;
}
