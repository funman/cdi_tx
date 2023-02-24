#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#include "util.h"

bool is_efa(void)
{
    FILE *f = fopen("/sys/class/infiniband_verbs/uverbs0/device/vendor", "r");
    if (!f)
        return false;

    unsigned int vendor;
    int ret = fscanf(f, "0x%0x", &vendor);
    fclose(f);

    if (ret != 1)
        return false;

    return vendor == 0x1d0f;
}

uint64_t now(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
        perror("clock_gettime");
        return 0;
    }

    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

uint16_t CalculateChecksum(const uint8_t *buf, int size, const uint8_t *csum_pos)
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
