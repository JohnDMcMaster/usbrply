# g++ -I../../uvudec/libuvudec -Wall -Werror main.cpp -lpcap -ldl -o uvusbreplay

USING_LIBUVUDEC=Y
#include ../common.mk

CFLAGS += -Wall -Werror

#PCAP_PREFIX=/home/mcmaster/document/prefix/libpcap-1.1.1

#CFLAGS += -I$(PCAP_PREFIX)/include

#PCAP_LIB_DIR = $(PCAP_PREFIX)/lib
#LFLAGS += -L$(PCAP_LIB_DIR)
#LFLAGS += -Wl,-rpath,$(PCAP_LIB_DIR)
LFLAGS += -lpcap
LFLAGS += -ldl

all:
	g++ $(CFLAGS) main.cpp $(LFLAGS) -o uvusbreplay
#	g++ $(CFLAGS) bulk.cpp $(LFLAGS) -o uvusbbulk

clean:
	rm -f uvusbreplay *~

