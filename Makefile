FABRIC=$(HOME)/libfabric/build/debug
export PKG_CONFIG_PATH=$(FABRIC)/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O2 -g `pkg-config --cflags libfabric`

all: tx

tx: tx.o

clean:
	rm -f tx *.o

run: tx
	LD_LIBRARY_PATH=$(FABRIC)/lib ./tx 192.168.0.221 192.168.0.177:47593
