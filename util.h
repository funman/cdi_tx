#include <inttypes.h>
#include <stdio.h>

#define unlikely(x)     __builtin_expect(!!(x),0)

#define RET(cmd)        \
do {                    \
    int ret = cmd;      \
    if (unlikely(ret)) {\
        fprintf(stderr, "%s():%d : ret=%d\n", __func__, __LINE__, ret); \
    }                   \
} while(0)

#define UBUF_DEFAULT_SIZE      8864
#define UBUF_DEFAULT_SIZE_A    8864

#define MAX_IP_STRING_LENGTH                (64)

#define MAX_IPV6_GID_LENGTH                 (32)
#define MAX_IPV6_ADDRESS_STRING_LENGTH      (64)
#define CDI_MAX_CONNECTION_NAME_STRING_LENGTH           (128)
#define CDI_MAX_STREAM_NAME_STRING_LENGTH               (CDI_MAX_CONNECTION_NAME_STRING_LENGTH+10)

typedef enum {
    kProbeStateIdle, // Waiting for ProtocolVersion
    kProbeStateEfaProbe, // Got ProtocolVersion, waiting for probe packets through EFA
    kProbeStateEfaTxProbeAcks, // Received probe packets, sends Connected
    kProbeStateEfaConnected, // Connected
} ProbeState;

typedef enum {
    kProbeCommandReset = 1, ///< Request to reset the connection. Start with 1 so no commands have the value 0.
    kProbeCommandPing,      ///< Request to ping the connection.
    kProbeCommandConnected, ///< Notification that connection has been established (probe has completed).
    kProbeCommandAck,       ///< Packet is an ACK response to a previously sent command.
    kProbeCommandProtocolVersion, ///< Packet contains protocol version of sender.
} ProbeCommand;

typedef enum {
    kPayloadTypeData = 0,   ///< Payload contains application payload data.
    kPayloadTypeDataOffset, ///< Payload contains application payload data with data offset field in each packet.
    kPayloadTypeProbe,      ///< Payload contains probe data.
    kPayloadTypeKeepAlive,  ///< Payload is being used for keeping the connection alive (don't use app payload
                            ///  callbacks).
} CdiPayloadType;

static void put_64le(uint8_t *buf, const uint64_t val)
{
    for (int i = 0; i < 8; i++)
        buf[i] = (val >> 8*i) & 0xff;
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

uint64_t now(void);
uint16_t CalculateChecksum(const uint8_t *buf, int size, const uint8_t *csum_pos);

