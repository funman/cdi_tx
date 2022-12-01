FABRIC=$(HOME)/libfabric/build/debug
export PKG_CONFIG_PATH=$(FABRIC)/lib/pkgconfig
LDLIBS += `pkg-config --libs libfabric`
CFLAGS += -O0 -g `pkg-config --cflags libfabric`

all: tx unconv rx

tx: tx.o util.o

rx: rx.o util.o

unconv: unconv.o

clean:
	rm -f tx rx unconv *.o

run: tx
	LD_LIBRARY_PATH=$(FABRIC)/lib ./run.sh

.PHONY: clean run
