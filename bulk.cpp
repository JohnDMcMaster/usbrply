#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
#include "uvd/util/error.h"
#include "uvd/util/util.h"
#include <limits.h>

#include "linux/usb/ch9.h"
#include "util.cpp"
     
unsigned int g_min_packet = 0;
unsigned int g_cur_packet = 0;
unsigned int g_max_packet = UINT_MAX;
bool g_error = false;
bool g_halt_error = true;
bool g_verbose = false;
FILE *g_out;

#define dbg(...) do { \
	if (g_verbose) { printf(__VA_ARGS__); } \
} while(0)

void loop_cb(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {
    uint8_t *dat_cur = 0;
    unsigned int len = 0;
	usb_urb_t *urb = NULL;
	size_t remaining_bytes = 0;
    	
	++g_cur_packet;
	if (g_cur_packet < g_min_packet || g_cur_packet > g_max_packet) {
		//printf("//Skipping packet %d\n", g_cur_packet);
		return;
	}
	
	if (header->caplen != header->len) {
		printf("packet %d: malformed, caplen %d != len %d\n",
			g_cur_packet, header->caplen, header->len );
		g_error = true;
		return;
	}
	len = header->len;
	remaining_bytes = len;
	dat_cur = (uint8_t *)packet;
	dbg("PACKET %u: length %u\n", g_cur_packet, len);
	//caplen is actual length, len is reported
	
	urb = (usb_urb_t *)dat_cur;
	remaining_bytes -= sizeof(*urb);
	dat_cur += sizeof(*urb);
	if (g_verbose) {
		printf("Packet %d (header size: %u)\n", g_cur_packet, sizeof(*urb));
		print_urb(urb);
	}
	
	if (urb->type == URB_ERROR) {
		printf("oh noes!\n");
		if (g_halt_error) {
			exit(1);
		}
	}

	if (urb->transfer_type != URB_BULK) {
        return;
    }

	if (URB_IS_IN(urb)) {
		if (urb->type == URB_COMPLETE) {
		    int rc = fwrite((const void *)dat_cur, 1, urb->data_length, g_out);
			if (rc != (int)urb->data_length) {
			    printf("Failed write (%d), expected %d on 0x%08X\n",
			            rc, urb->data_length, (int)urb->data);
			    exit(1);
			}
		}		
    }
}

void usage() {
	printf("uvusbreplay [options] <input .cap>\n");
	printf("Options:\n");
	printf("-r <min-max>: use packet range, default all, 1 indexed (since Wireshark does), inclusive\n");
	printf("-k: format output for Linux kernel (default)\n");
	printf("-l: format output for libusb\n");
	printf("-n: no packet numbering\n");
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p = NULL;
	
	opterr = 0;

	while (true) {
		int c = getopt(argc, argv, "r:klh?vsfn");
		
		if (c == -1) {
			break;
		}
		
		switch (c)
		{
			case 'r':
			{
				if (UV_FAILED(parseNumericRangeString(optarg, &g_min_packet, &g_max_packet))) {
					printf("Invalid range string %s\n", optarg);
					usage();
					exit(1);
				}
				break;
			}
			
			case 'h':
			case '?':
				usage();
				exit(1);
				break;
			
			case 'v':
				g_verbose = true;
				break;
			
			default:
				printf("Unknown argument %c\n", c);
				usage();
				exit(1);
		}
	}
	
	std::string fileNameIn = "in.cap";
	std::string fileNameOut = "out.bin";
 
	if (optind < argc) {
		fileNameIn = argv[optind];
		++optind;
	}
	if (optind < argc) {
		fileNameOut = argv[optind];
		++optind;
	}
	
	dbg("parsing from range %u to %u\n", g_min_packet, g_max_packet);
	p = pcap_open_offline(fileNameIn.c_str(), errbuf);
	if (p == NULL) {
		printf("failed to open %s\n", fileNameIn.c_str());
		exit(1);
	}
	g_out = fopen(fileNameOut.c_str(), "w");
	if (!g_out) {
		printf("failed to open %s\n", fileNameOut.c_str());
		exit(1);
	}
	
	pcap_loop(p, -1, loop_cb, NULL);
	
	return 0;
}

