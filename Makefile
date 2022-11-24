FABRIC=$(HOME)/libfabric/build/debug
export PKG_CONFIG_PATH=$(FABRIC)/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O0 -g `pkg-config --cflags libfabric`

all: tx unconv

tx: tx.o

unconv: unconv.o

clean:
	rm -f tx unconv *.o

run: tx
	LD_LIBRARY_PATH=$(FABRIC)/lib ./run.sh

.PHONY: clean run
