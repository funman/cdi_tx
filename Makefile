FABRIC=$(HOME)/libfabric/build/debug
export PKG_CONFIG_PATH=$(FABRIC)/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O0 -g `pkg-config --cflags libfabric`

all: tx

tx: tx.o

clean:
	rm -f tx *.o

run: tx
	(while :;do cat f;done)|FI_LOG_LEVEL=10 LD_LIBRARY_PATH=$(FABRIC)/lib ./tx 192.168.0.221 192.168.0.177:47593
