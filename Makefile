FABRIC=$(HOME)/libfabric/build/debug
export PKG_CONFIG_PATH=$(FABRIC)/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O2 -g `pkg-config --cflags libfabric`

all: tx

tx: tx.o

clean:
	rm -f tx *.o

run: tx
	FI_LOG_LEVEL=10 LD_LIBRARY_PATH=$(FABRIC)/lib gdb -q --args ./tx 192.168.0.221 192.168.0.177:47593
