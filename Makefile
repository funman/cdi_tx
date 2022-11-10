export PKG_CONFIG_PATH=/home/fun/libfabric/build/debug/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O2 -g `pkg-config --cflags libfabric`

all: tx

tx: tx.o

clean:
	rm -f tx *.o
