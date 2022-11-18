#include <stdio.h>
#include <inttypes.h>

int main(void)
{
    uint16_t uyvy[1920*1080*2];
    for (;;) {
        if (fread(uyvy, sizeof(uyvy), 1, stdin) != 1)
            return 1;

        for (int i = 0; i < 1920*1080; i+=2) {
            uint8_t a,b,c,d,e;
            a = uyvy[1920*1080+i/2] >> 2;
            b = (uyvy[1920*1080+i/2] & 0x3) << 6;
            b |= (uyvy[i] >> 4) & 0x3f;
            c = (uyvy[i] & 0xf) << 4;
            c |= (uyvy[1920*1080*3/2+i/2] >> 6) & 0xf;
            d = (uyvy[1920*1080*3/2+i/2] & 0x3f) << 2;
            d |= (uyvy[i+1] >> 8) & 0x3;
            e = uyvy[i+1] & 0xff;
            putchar(a);
            putchar(b);
            putchar(c);
            putchar(d);
            putchar(e);
        }
    }

    return 0;
}
