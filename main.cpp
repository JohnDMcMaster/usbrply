/*
I write a lot of nice code...this is not bad but not pretty either

Wanted to do this in python but couldn't get python bindings to work even after trying newest version of libpcap
Expect the Lua bindings are out of date and I don't feel like messing with them
Python is good for dev, but SIGSEGV in Python is ugly...
*/




#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string>
//#include "uvd/util/error.h"
//#include "uvd/util/util.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "util.cpp" 
     
typedef enum {
	//Linux kernel
	OUTPUT_LINUX,
	//libusb
	OUTPUT_LIBUSB,
	//libusb (python)
	OUTPUT_LIBUSBPY,
} output_target_t;
output_target_t g_output_target = OUTPUT_LINUX;

unsigned int g_min_packet = 0;
unsigned int g_cur_packet = 0;
unsigned int g_max_packet = UINT_MAX;
bool g_error = false;
bool g_halt_error = true;
bool g_verbose = false;
bool g_allow_short = false;
bool g_custom_call = false;
bool g_use_defines = false;
bool g_packet_numbers = true;

#define VERSION_STR		"0.1"

#define dbg(...) do { \
	if (g_verbose) { printf(__VA_ARGS__); } \
} while(0)



//Output printf
#define oprintf		printf

//When we get an IN request we may process packets in between
class PendingRX {
public:
	usb_urb_t m_urb;
	usb_ctrlrequest m_ctrl;
	unsigned int packet_number;
	uint8_t *m_data_out;
	size_t m_data_out_size;

    PendingRX() {
        m_data_out = NULL;
        m_data_out_size = 0;
    }
    //really this should be destructor but copying it around...
    void free() {
        ::free(m_data_out);
    }
};

//Pending control requests
std::map<uint64_t, PendingRX> g_pending_control;

bool keep_packet( const PendingRX *in );
bool keep_packet( const PendingRX &in );

bool keep_packet( const PendingRX *in ) {
    return keep_packet(*in);
}

bool keep_packet( const PendingRX &in ) {
	//grr forgot I had this on
	//return (in.m_urb.transfer_type & URB_CONTROL) && (in.m_ctrl.bRequestType & USB_DIR_IN);
	return true;
}

typedef struct {
	unsigned req_in;
	unsigned req_in_last;
	unsigned in;
	unsigned in_last;
	
	unsigned req_out;
	unsigned req_out_last;
	unsigned out;
	unsigned out_last;
} payload_bytes_type_t;
typedef struct {
	payload_bytes_type_t ctrl;
	payload_bytes_type_t bulk;
} payload_bytes_t;
payload_bytes_t g_payload_bytes;

std::string UVDSprintf(const char *format, ...)
{
	//TODO: should we try buffering the memory to increase performance?
	//Think during UVDInit we should reserve a modest buffer for the common case
	char *buff = NULL;
	size_t needed = 0;
	std::string ret;
	va_list ap;
	
	va_start(ap, format);
	needed = vsnprintf(NULL, 0, format, ap) + 1;
	va_end(ap);
 	
	buff = (char *)malloc(sizeof(buff[0]) * needed);
	if( !buff )
	{
		return "";
	}

	va_start(ap, format);
	vsnprintf(buff, needed, format, ap);
	va_end(ap);

	ret = buff;
	free(buff);
	return ret;
}

void update_delta( payload_bytes_type_t *in ) {
	in->req_in_last = in->req_in;
	in->in_last = in->in;

	in->req_out_last = in->req_out;
	in->out_last = in->out;
}


void processControlSubmit(usb_urb_t *urb, uint8_t *dat_cur, unsigned int remaining_bytes) {
	struct usb_ctrlrequest *ctrl = NULL;
	PendingRX pending;
	
	pending.m_urb = *urb;
	if (remaining_bytes < sizeof(*ctrl)) {
		printf("packet %d: got %d instead of min header length %lu\n",
				g_cur_packet, remaining_bytes, sizeof(*ctrl));
		g_error = true;
		return;
	}

    ctrl = (struct usb_ctrlrequest *)dat_cur;
	remaining_bytes -=  sizeof(*ctrl);
	dat_cur += sizeof(*ctrl);
	
	//FIXME: some mystery bytes that I don't understand
	if (remaining_bytes < 16) {
		printf("packet %d: missing mystery bytes\n",
				g_cur_packet);
		g_error = true;
		return;
	}
	remaining_bytes -= 16;
	dat_cur += 16;
	
	
	if (g_verbose) {
		printf("Packet %d control submit (control info size %lu)\n", g_cur_packet, sizeof(*ctrl));
		printf("\tbRequestType: %s (0x%02X)\n", get_request_type_str(ctrl->bRequestType).c_str(), ctrl->bRequestType);
		printf("\tbRequest: %s (0x%02X)\n", get_request_str( ctrl->bRequestType, ctrl->bRequest ).c_str(), ctrl->bRequest);
		printf("\twValue: 0x%04X\n", ctrl->wValue);
		printf("\twIndex: 0x%04X\n", ctrl->wIndex);
		printf("\twLength: 0x%04X\n", ctrl->wLength);
	}
	
	if ((ctrl->bRequestType & USB_DIR_IN) == USB_DIR_IN) {
		dbg("%d: IN\n", g_cur_packet);
	} else {
		dbg("%d: OUT\n", g_cur_packet);
		if (remaining_bytes != urb->data_length) {
		    printf("remaining bytes %d != expected payload out bytes %d\n",
				    remaining_bytes, urb->data_length);
        	UVDHexdumpCore((const uint8_t *)dat_cur, remaining_bytes, "  ");
		    g_error = true;
		    return;
		}
		pending.m_data_out = (uint8_t *)malloc(urb->data_length);
		if (pending.m_data_out == NULL) {
		    printf("failed alloc\n");
		    g_error = true;
		    return;
		}
		memcpy(pending.m_data_out, dat_cur, urb->data_length);
		pending.m_data_out_size = urb->data_length;
	}
    pending.m_ctrl = *ctrl;
    pending.packet_number = g_cur_packet;
    g_pending_control[urb->id] = pending;	
}

void printControlRequest(PendingRX *submit,
        const std::string &data_str, unsigned int data_size,
        const std::string &pipe_str) {

    /*
    unsigned int dev_control_message(int requesttype, int request,
            int value, int index, char *bytes, int size) {
            
    WARNING: request / request type parameters are swapped between kernel and libusb
    request type is clearly listed first in USB spec and seems more logically first so I'm going to blame kernel on this
    although maybe libusb came after and was trying for multi OS comatibility right off the bat
    
    Anyway, use dev_control_message for finer grained (eg macro) support

    libusb
    int usb_control_msg(usb_dev_handle *dev, int requesttype, int request, int value, int index, char *bytes, int size, int timeout);

    kernel
    extern int usb_control_msg(struct usb_device *dev, unsigned int pipe,
        __u8 request, __u8 requesttype, __u16 value, __u16 index,
        void *data, __u16 size, int timeout);
    
    Example output:
    n_rw = dev_ctrl_msg(0x0B, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0xAD16, 0xAD15, buff, 1, 500);
    
    def controlWrite(self, request_type, request, value, index, data, timeout=0):
    def controlRead(self, request_type, request, value, index, length, timeout=0):
    self.dev.controlWrite(0x40, 0x00, 0x0001, 0x0001, '')
    */
    if (g_output_target == OUTPUT_LIBUSBPY) {
        //std::string bRequestStr = get_request_str( submit->m_ctrl.bRequestType, submit->m_ctrl.bRequest );
        //std::string bRequestTypeStr = get_request_type_str(submit->m_ctrl.bRequestType);
	    if (submit->m_ctrl.bRequestType & USB_DIR_IN) {
	        oprintf("buff = self.dev.controlRead(0x%02X, 0x%02X, 0x%04X, 0x%04X, %u)\n",
			        submit->m_ctrl.bRequestType, submit->m_ctrl.bRequest,
			        submit->m_ctrl.wValue, submit->m_ctrl.wIndex, data_size);
        } else {
	        oprintf("self.dev.controlWrite(0x%02X, 0x%02X, 0x%04X, 0x%04X, %s)\n",
			        submit->m_ctrl.bRequestType, submit->m_ctrl.bRequest,
			        submit->m_ctrl.wValue, submit->m_ctrl.wIndex,
			        data_str.c_str());
        }
    } else {
    	std::string timeout;
        oprintf("n_rw = ");
        if (g_custom_call) {
            oprintf("dev_ctrl_msg(");
        } else {
            std::string device_str = "g_dev";
            oprintf("usb_control_msg(%s, ", device_str.c_str());
        }
        
	    if (g_output_target == OUTPUT_LINUX) {
            oprintf("%s", pipe_str.c_str());
        }
        
        std::string bRequestStr = get_request_str( submit->m_ctrl.bRequestType, submit->m_ctrl.bRequest );
        std::string bRequestTypeStr = "";
        
        if (g_output_target == OUTPUT_LIBUSB && !g_use_defines) {
            bRequestTypeStr = UVDSprintf("0x%02X", submit->m_ctrl.bRequestType);
        } else {
            bRequestTypeStr = get_request_type_str(submit->m_ctrl.bRequestType);
        }
	
	    if (g_output_target == OUTPUT_LIBUSB) {
	        oprintf("%s, %s, ", bRequestTypeStr.c_str(), bRequestStr.c_str());
	    } else {
	        oprintf("%s, %s, ", bRequestStr.c_str(), bRequestTypeStr.c_str());
	    }
	
	    if (g_custom_call) {
	        timeout = "";
	    } else {
	        timeout = ", 500";
	    }
	
	    oprintf("0x%04X, 0x%04X, %s, %u%s);\n",
			    submit->m_ctrl.wValue, submit->m_ctrl.wIndex,
			    data_str.c_str(), data_size,
			    timeout.c_str() );
    }
}

std::string bytes2AnonArray(const void *in, size_t in_size, const char *byte_type = "uint8_t") {
    if (g_output_target == OUTPUT_LIBUSBPY) {
        std::string byte_str = "\"";
	    const uint8_t *payload = (const uint8_t*)in;
	
	    for (unsigned int i = 0; i < in_size; ++i) {
		    byte_str += UVDSprintf("\\x%02X", payload[i]);
	    }
	    return byte_str + "\"";
    } else {
        std::string byte_str = UVDSprintf("(%s[]){", byte_type);
	    std::string pad = "";
	    const uint8_t *payload = (const uint8_t*)in;
	
	    for (unsigned int i = 0; i < in_size; ++i) {
		    if (i % 16 == 0) {
		        pad = "";
		        if (i != 0) {
		            byte_str += ",\n        ";
		        }
		    }
		    byte_str += pad;
		    byte_str += UVDSprintf("0x%02X", payload[i]);
		    pad = ", ";
	    }
	    return byte_str + "}";
    }
}

std::string deviceStr() {
	//return "dev->udev";
	return "udev";
}

void processControlCompleteIn(PendingRX *submit, uint8_t *dat_cur, unsigned int remaining_bytes) {
    std::string packet_numbering;
	unsigned int data_size = 0;
	std::string data_str = "NULL";
	unsigned int max_payload_sz = submit->m_ctrl.wLength;
	
	//Is it legal to have a 0 length control in?
	if (submit->m_ctrl.wLength) {
		data_str = "buff";
		data_size = submit->m_ctrl.wLength;
	} else if (g_output_target == OUTPUT_LIBUSBPY) {
	    data_str = "\"\"";
	}
	
	if (keep_packet(submit)) {
	    printControlRequest(submit, data_str, data_size,
	            UVDSprintf( "usb_rcvctrlpipe(%s, 0), ", deviceStr().c_str() ) );
	}
	
	//Take off the unknown struct
	if (remaining_bytes < sizeof(control_rx_t)) {
		printf("not enough data\n");
		if (g_halt_error) {
			exit(1);
		}
		return;
	}
	dat_cur += sizeof(control_rx_t);
	remaining_bytes -= sizeof(control_rx_t);
	//Now dat_cur/remaining_bytes is the control in data payload
	
	//Verify we actually have enough / expected
    //If exact match don't care
	if (remaining_bytes != max_payload_sz) {
	    if (g_allow_short && remaining_bytes < max_payload_sz) {
            printf("//WARNING: shrinking response, max %u but got %u\n", max_payload_sz, remaining_bytes);
        } else {
	        printf("expected remaining bytes %u to be the requested length %u\n",
			        remaining_bytes, max_payload_sz );
	        if (g_halt_error) {
		        exit(1);
	        }
	        return;
        }
    }
    
    if (submit->m_ctrl.wLength) {
        if (g_packet_numbers) {
            packet_numbering = UVDSprintf("packet %u/%u",
                    submit->packet_number, g_cur_packet);
        } else {
            //TODO: consider counting instead of by captured index
            packet_numbering = "packet";
        }

	    if (g_output_target == OUTPUT_LIBUSBPY) {
		    oprintf("validate_read(%s, buff, \"%s\")\n",
			    bytes2AnonArray(dat_cur, remaining_bytes, "char").c_str(), 
			    packet_numbering.c_str() );
	    } else {
		    oprintf("validate_read(%s, %u, buff, n_rw, \"%s\");\n",
			    bytes2AnonArray(dat_cur, remaining_bytes, "char").c_str(), remaining_bytes, 
			    packet_numbering.c_str() );
	    }
	}
}

void processControlCompleteOut(PendingRX *submit, uint8_t *dat_cur, unsigned int remaining_bytes) {
	unsigned int data_size = 0;
	std::string data_str = "NULL";
	
    //printf("Data out size: %u vs urb size %u\n", submit->m_data_out_size, submit->m_urb.data_length );
	if (submit->m_data_out_size) {
	    //Note that its the submit from earlier, not the ack that we care about
        data_str = bytes2AnonArray(submit->m_data_out, submit->m_data_out_size);
        data_size = submit->m_data_out_size;
	} else if (g_output_target == OUTPUT_LIBUSBPY) {
	    data_str = "\"\"";
	}
	
	if (keep_packet(submit)) {
	    printControlRequest(submit, data_str, data_size,
	            UVDSprintf( "usb_sndctrlpipe(%s, 0), ", deviceStr().c_str()) );
	}
}

void processControlComplete(PendingRX *submit, uint8_t *dat_cur, unsigned int remaining_bytes) {
	if (false && keep_packet(submit)) {
		payload_bytes_type_t *bulk = &g_payload_bytes.bulk;
		//payload_bytes_type_t *ctrl = &g_payload_bytes.ctrl;
		
		printf("Transer statistics\n");
		printf("\tBulk\n");
		printf("\t\tIn: %u (delta %u), req: %u (delta %u)\n",
				bulk->in, bulk->in - bulk->in_last,
				bulk->req_in, bulk->req_in - bulk->req_in_last
				);
		update_delta( bulk );
		printf("\t\tOut: %u, req: %u\n", g_payload_bytes.bulk.out, g_payload_bytes.bulk.req_out);
		printf("\tControl\n");
		printf("\t\tIn: %u, req: %u\n", g_payload_bytes.ctrl.in, g_payload_bytes.ctrl.req_in);
		printf("\t\tOut: %u, req: %u\n", g_payload_bytes.ctrl.out, g_payload_bytes.ctrl.req_out);
	}
	
	if (!keep_packet(submit)) {
	    return;
	}
	if (g_packet_numbers) {
        if (g_output_target == OUTPUT_LIBUSBPY) {
		    oprintf("# Generated from packet %u/%u\n", submit->packet_number, g_cur_packet);
	    } else {
		    oprintf("//Generated from packet %u/%u\n", submit->packet_number, g_cur_packet);
	    }
	}
	if (submit->m_ctrl.bRequestType & USB_DIR_IN) {
	    processControlCompleteIn(submit, dat_cur, remaining_bytes);
	} else {
	    processControlCompleteOut(submit, dat_cur, remaining_bytes);
	}
	
}

void processBulk(usb_urb_t *urb, uint8_t *dat_cur, unsigned int remaining_bytes) {
	//TODO: do something for bulk transfers?
	//Don't care about this but populate for now
	//g_pending_control[urb->id] = pending;

	if (URB_IS_IN(urb)) {
		switch (urb->type) {
		case URB_SUBMIT:
			g_payload_bytes.bulk.req_in += urb->length;
			break;
		case URB_COMPLETE:
			g_payload_bytes.bulk.in += urb->data_length;
			break;
		}		
	} else {	
		switch (urb->type) {
		case URB_SUBMIT:
			g_payload_bytes.bulk.req_out += urb->length;
			break;
		case URB_COMPLETE:
			g_payload_bytes.bulk.out += urb->data_length;
			break;
		}
	}
}

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
	if (0) {
	    printf("PACKET %u: length %u\n", g_cur_packet, len);
    	UVDHexdumpCore(dat_cur, remaining_bytes, "  ");
	}

	//caplen is actual length, len is reported
	
	urb = (usb_urb_t *)dat_cur;
	remaining_bytes -= sizeof(*urb);
	dat_cur += sizeof(*urb);
	if (g_verbose) {
		printf("Packet %d (header size: %lu)\n", g_cur_packet, sizeof(*urb));
		print_urb(urb);
	}
	if (0) {
	    printf("PACKET %u: URB\n", g_cur_packet);
    	UVDHexdumpCore((const uint8_t *)urb, sizeof(*urb), "  ");
	}
	
	if (urb->type == URB_ERROR) {
		printf("oh noes!\n");
		if (g_halt_error) {
			exit(1);
		}
	}

	//Find the matching submit request
	PendingRX submit;
	if( urb->type == URB_COMPLETE) {
		if (g_pending_control.find(urb->id) == g_pending_control.end()) {
			printf("WTF?  packet %d missing control URB end.  URB ID: 0x%016lX\n", g_cur_packet, urb->id);
			if (g_halt_error) {
				exit(1);
			}
		}
		submit = g_pending_control[urb->id];
		//Done with it, get rid of it
		g_pending_control.erase(g_pending_control.find(urb->id));
		if (!g_pending_control.empty()) {
			//printf("WARNING: out of order traffic packet around %u, not too much thought put into that\n", g_cur_packet);
		}
	}
	
	if (urb->transfer_type == URB_CONTROL) {
		if (urb->type == URB_SUBMIT) {
		    processControlSubmit(urb, dat_cur, remaining_bytes);
		} else if(urb->type == URB_COMPLETE) {
		    processControlComplete(&submit, dat_cur, remaining_bytes);
        } else {
			printf("WTF? %d\n", __LINE__);
			if (g_halt_error) {
				exit(1);
			}
		}
	} else if (urb->transfer_type == URB_BULK) {
	    processBulk(urb, dat_cur, remaining_bytes);
	}
	
	if( urb->type == URB_COMPLETE) {
		//Done...release buffers if any
        submit.free();
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
		int c = getopt(argc, argv, "r:klh?vsfnp");
		
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
			
			case 'k':
				g_output_target = OUTPUT_LINUX;
				break;
			
			case 'l':
				g_output_target = OUTPUT_LIBUSB;
				break;
			
			case 'p':
				g_output_target = OUTPUT_LIBUSBPY;
				break;
			
			case 's':
				g_allow_short = true;
				break;
			
			case 'f':
			    g_custom_call = true;
			    break;
			
			case 'n':
			    g_packet_numbers = false;
			    break;
			
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
	
	std::string fileName = "in.cap";
    //"/home/mcmaster/document/external/uvscopetek/captures/twain_image/wireshark/1/640x320_wireshark.cap"
 
	unsigned int raws = 0;
	for (int index = optind; index < argc; index++) {
		if (raws == 0) {
			fileName = argv[index];
		} else {
			printf("Too many args\n");
			usage();
			exit(1);
		}
		++raws;
	}
	
	oprintf("/*\n");
	oprintf("Generated by uvusbreplay %s\n", VERSION_STR);
	oprintf("uvusbreplay copyright 2011 John McMaster <JohnDMcMaster@gmail.com>\n");
	//oprintf("Date: %s\n", UVDCurDateTime().c_str());
	oprintf("Source data: %s\n", fileName.c_str());
	oprintf("Source range: %u - %u\n", g_min_packet, g_max_packet);
	oprintf("*/\n");
	oprintf("int n_rw = 0;\n");
	oprintf("uint8_t buff[4096];\n");
	
	if (g_output_target == OUTPUT_LIBUSB && g_use_defines) {
	    //Libusb expects users to hard code these into address I guess
        oprintf("//Directions\n");
        oprintf("//to device\n");
        oprintf("const int USB_DIR_OUT = 0;\n");
        oprintf("//to host\n");
        oprintf("const int USB_DIR_IN = 0x80;\n");
        oprintf("const int USB_TYPE_MASK = (0x03 << 5);\n");
        oprintf("const int USB_TYPE_STANDARD = (0x00 << 5);\n");
        oprintf("const int USB_TYPE_CLASS = (0x01 << 5);\n");
        oprintf("const int USB_TYPE_VENDOR = (0x02 << 5);\n");
        oprintf("const int USB_TYPE_RESERVED = (0x03 << 5);\n");
	}
    oprintf("\n");
	
	dbg("parsing from range %u to %u\n", g_min_packet, g_max_packet);
	p = pcap_open_offline(fileName.c_str(), errbuf);
	if (p == NULL) {
		printf("failed to open %s\n", fileName.c_str());
		exit(1);
	}
	pcap_loop(p, -1, loop_cb, NULL);
	
	if (!g_pending_control.empty()) {
		printf("WARNING: %lu pending requests\n", g_pending_control.size());
	}
	//Makes copy/pasting easier in some editors...
	oprintf("\n");
	
	return 0;
}

