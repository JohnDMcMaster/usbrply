#!/usr/bin/env python

'''
2:30: keish into oven


uvusbreplay-py 01_prog2.cap
sudo pip install pycap

I write a lot of nice code...this is not bad but not pretty either

Wanted to do this in python but couldn't get python bindings to work even after trying newest version of libpcap
Expect the Lua bindings are out of date and I don't feel like messing with them
Python is good for dev, but SIGSEGV in Python is ugly...
'''

import pcap
import argparse
import sys
import binascii
import struct
from collections import namedtuple

# Linux kernel
OUTPUT_LINUX = 'LINUX'
# libusb
OUTPUT_LIBUSB = 'LIBUSB'
OUTPUT_LIBUSBPY = 'LIBUSBPY'
# output_target_t
#args.ofmt = 'OUTPUT_LINUX'

g_min_packet = 0
g_max_packet = float('inf')
g_error = False
g_halt_error = True
g_verbose = False
g_allow_short = False
g_custom_call = False
g_use_defines = False
g_packet_numbers = True

VERSION_STR    = "0.1"


'''
pcap/usb.h compat
'''

'''
possible transfer mode
'''
URB_TRANSFER_IN =   0x80
URB_ISOCHRONOUS =   0x0
URB_INTERRUPT =     0x1
URB_CONTROL =       0x2
URB_BULK =          0x3

'''
possible event type
'''
URB_SUBMIT =        ord('S')
URB_COMPLETE =      ord('C')
URB_ERROR =         ord('E')



def dbg(args):
    if g_verbose:
        print args

# When we get an IN request we may process packets in between
class PendingRX:
    def __init__(self):
        #usb_urb_t m_urb
        self.m_urb = None
        #usb_ctrlrequest m_ctrl
        self.m_ctrl = None
        self.packet_number = 0
        
        # uint8_t *m_data_out
        self.m_data_out = None

"""
# Pending control requests
#std::map<uint64_t, PendingRX> g_pending_control
"""
g_pending_control = {}

def keep_packet( _in ):
    # grr forgot I had this on
    # return (in.m_urb.transfer_type & URB_CONTROL) and (in.m_ctrl.bRequestType & URB_TRANSFER_IN)
    return True


class payload_bytes_type_t:
    def __init__(self):
        req_in = None
        self.req_in_last = None
        self.in_ = None
        self.in_last = None
    
        self.req_out = None
        self.req_out_last = None
        self.out = None
        self.out_last = None

class payload_bytes_t:
    def __init__(self):
        self.ctrl = payload_bytes_type_t()
        self.bulk = payload_bytes_type_t()
g_payload_bytes = payload_bytes_t()

def update_delta( pb ):
    pb.req_in_last = pb.req_in
    pb.in_last = pb.in_

    pb.req_out_last = pb.req_out
    pb.out_last = pb.out

'''
struct usb_ctrlrequest {
    __u8 bRequestType;
    __u8 bRequest;
    __le16 wValue;
    __le16 wIndex;
    __le16 wLength;
} __attribute__ ((packed));
'''
usb_ctrlrequest_nt = namedtuple('usb_ctrlrequest', ('bRequestType',
        'bRequest',
        'wValue',
        'wIndex',
        'wLength',
        # FIXME: some mystery bytes that I don't understand
        'res'))
usb_ctrlrequest_fmt = '<BBHHHH'
usb_ctrlrequest_sz = struct.calcsize(usb_ctrlrequest_fmt)
def usb_ctrlrequest(s):
    return  usb_ctrlrequest_nt(*struct.unpack(usb_ctrlrequest_fmt, str(s)))




'''
//TODO; figure out what this actually is
typedef struct {
    uint8_t raw[24];
} __attribute__((packed)) control_rx_t;
'''
control_rx_sz = 3
def control_rx(s):
    return s



def printControlRequest(submit, data_str, data_size, pipe_str):
    '''
    unsigned int dev_control_message(int requesttype, int request,
            int value, int index, char *bytes, int size):
            
    WARNING: request / request type parameters are swapped between kernel and libusb
    request type is clearly listed first in USB spec and seems more logically first so I'm going to blame kernel on this
    although maybe libusb came after and was trying for multi OS comatibility right off the bat
    
    Anyway, use dev_control_message for finer grained (eg macro) support

    libusb
    int usb_control_msg(usb_dev_handle *dev, int requesttype, int request, int value, int index, char *bytes, int size, int timeout)

    kernel
    extern int usb_control_msg(struct usb_device *dev, unsigned int pipe,
        __u8 request, __u8 requesttype, __u16 value, __u16 index,
        def *data, __u16 size, int timeout)
    
    Example output:
    n_rw = dev_ctrl_msg(0x0B, URB_TRANSFER_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE, 0xAD16, 0xAD15, buff, 1, 500)


    def controlWrite(self, request_type, request, value, index, data, timeout=0):
    def controlRead(self, request_type, request, value, index, length, timeout=0):
    self.dev.controlWrite(0x40, 0x00, 0x0001, 0x0001, '')
    '''
    
    if args.ofmt == OUTPUT_LIBUSBPY:
        #std::string bRequestStr = get_request_str( submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest )
        #std::string bRequestTypeStr = get_request_type_str(submit.m_ctrl.bRequestType)
        if (submit.m_ctrl.bRequestType & URB_TRANSFER_IN):
            print "buff = self.dev.controlRead(0x%02X, 0x%02X, 0x%04X, 0x%04X, %u)" % (submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest,
                    submit.m_ctrl.wValue, submit.m_ctrl.wIndex, data_size)
        else:
            print "self.dev.controlWrite(0x%02X, 0x%02X, 0x%04X, 0x%04X, %s)" % (submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest,
                    submit.m_ctrl.wValue, submit.m_ctrl.wIndex, data_str)
    else:
        timeout = ''
        out = ''
    
        print "n_rw = "
        if (g_custom_call):
            out += "dev_ctrl_msg("
        else:
            device_str = "g_dev"
            out += "usb_control_msg(%s, ", device_str
        
        
        if args.ofmt == OUTPUT_LINUX:
            out += "%s", pipe_str
        
        
        bRequestStr = request_type2str[ submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest ]
        bRequestTypeStr = ""
        
        if args.ofmt == OUTPUT_LIBUSB and not g_use_defines:
            bRequestTypeStr = "0x%02X" % submit.m_ctrl.bRequestType
        else:
            bRequestTypeStr = request_type2str[submit.m_ctrl.bRequestType]
        
        
        if args.ofmt == OUTPUT_LIBUSB:
            out += "%s, %s, " % (bRequestTypeStr, bRequestStr)
        else:
            out += "%s, %s, " % (bRequestStr, bRequestTypeStr)
        
        
        if (g_custom_call):
            timeout = ""
        else:
            timeout = ", 500"
        
        
        out += "0x%04X, 0x%04X, %s, %u%s);" % (
                submit.m_ctrl.wValue, submit.m_ctrl.wIndex,
                data_str, data_size,
                timeout )
        print out

def bytes2AnonArray(in_, byte_type = "uint8_t"):
    if args.ofmt == OUTPUT_LIBUSBPY:
        byte_str = "\""
        payload = str(in_)
    
        for i in xrange(len(payload)):
            byte_str += "\\x%02X" % (payload[i],)
        return byte_str + "\""
    else:
        byte_str = "(%s[]){" % (byte_type,)
        pad = ""
        payload = str(in_)
        
        for i in xrange(len(payload)):
            if i % 16 == 0:
                pad = ""
                if i != 0:
                    byte_str += ",\n        "
                
            byte_str += pad
            byte_str += "0x%02X" % payload[i]
            pad = ", "
        
        return byte_str + "}"


def deviceStr():
    # return "dev.udev"
    return "udev"

def processBulk(urb, dat_cur):
    raise Exception("FIXME")

"""
def processBulk(usb_urb_t *urb, dat_cur):
    # TODO: do something for bulk transfers?
    # Don't care about this but populate for now
    # g_pending_control[urb.id] = pending

    if (URB_IS_IN(urb)):
        switch (urb.type):
        case URB_SUBMIT:
            g_payload_bytes.bulk.req_in += urb.length
            break
        case URB_COMPLETE:
            g_payload_bytes.bulk.in += urb.data_length
            break
        }        
    else {    
        switch (urb.type):
        case URB_SUBMIT:
            g_payload_bytes.bulk.req_out += urb.length
            break
        case URB_COMPLETE:
            g_payload_bytes.bulk.out += urb.data_length
            break
        
"""
    
def sizeof(*args):
    raise Exception('FIXME')


urb_type2str = {
        URB_SUBMIT: 'URB_SUBMIT',
        URB_COMPLETE: 'URB_COMPLETE',
        URB_ERROR: 'URB_ERROR',
        }


transfer2str = {
        URB_ISOCHRONOUS: "URB_ISOCHRONOUS",
        URB_INTERRUPT: "URB_INTERRUPT",
        URB_CONTROL: "URB_CONTROL",
        URB_BULK: "URB_BULK",
        }


USB_REQ_GET_STATUS =        0x00
USB_REQ_CLEAR_FEATURE =     0x01
# 0x02 is reserved
USB_REQ_SET_FEATURE =       0x03
# 0x04 is reserved
USB_REQ_SET_ADDRESS =       0x05
USB_REQ_GET_DESCRIPTOR =    0x06
USB_REQ_SET_DESCRIPTOR =    0x07
USB_REQ_GET_CONFIGURATION = 0x08
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_GET_INTERFACE =     0x0A
USB_REQ_SET_INTERFACE =     0x0B
USB_REQ_SYNCH_FRAME =       0x0C

USB_DIR_OUT =               0       # to device
USB_DIR_IN =                0x80    # to host

USB_TYPE_MASK =             (0x03 << 5)
USB_TYPE_STANDARD =         (0x00 << 5)
USB_TYPE_CLASS =            (0x01 << 5)
USB_TYPE_VENDOR =           (0x02 << 5)
USB_TYPE_RESERVED =         (0x03 << 5)

USB_RECIP_MASK =            0x1f
USB_RECIP_DEVICE =          0x00
USB_RECIP_INTERFACE =       0x01
USB_RECIP_ENDPOINT =        0x02
USB_RECIP_OTHER =           0x03
# From Wireless USB 1.0
USB_RECIP_PORT =            0x04
USB_RECIP_RPIPE =           0x05


def request2str(bRequestType, bRequest):
    bRequestType = bRequestType & USB_TYPE_MASK
    m = {
        USB_TYPE_STANDARD: {
            USB_REQ_GET_STATUS:         "USB_REQ_GET_STATUS",
            USB_REQ_CLEAR_FEATURE:      "USB_REQ_CLEAR_FEATURE",
            USB_REQ_SET_FEATURE:        "USB_REQ_SET_FEATURE",
            USB_REQ_SET_ADDRESS:        "USB_REQ_SET_ADDRESS",
            USB_REQ_GET_DESCRIPTOR:     "USB_REQ_GET_DESCRIPTOR",
            USB_REQ_SET_DESCRIPTOR:     "USB_REQ_SET_DESCRIPTOR",
            USB_REQ_GET_CONFIGURATION:  "USB_REQ_GET_CONFIGURATION",
            USB_REQ_SET_CONFIGURATION:  "USB_REQ_SET_CONFIGURATION",
            USB_REQ_GET_INTERFACE:      "USB_REQ_GET_INTERFACE",
            USB_REQ_SET_INTERFACE:      "USB_REQ_SET_INTERFACE",
            USB_REQ_SYNCH_FRAME:        "USB_REQ_SYNCH_FRAME",  
        }
    }
    n = m.get(bRequestType, None)
    if n is None:
        return "0x%02X" % bRequest
    return n[bRequest]


def request_type2str(bRequestType):
    ret = "";
    
    if (bRequestType & USB_DIR_IN) == USB_DIR_IN:
        ret += "USB_DIR_IN"
    else:
        ret += "USB_DIR_OUT"
    
    m = {
        USB_TYPE_STANDARD: " | USB_TYPE_STANDARD" ,
        USB_TYPE_CLASS: " | USB_TYPE_CLASS" ,
        USB_TYPE_VENDOR: " | USB_TYPE_VENDOR", 
        USB_TYPE_RESERVED: " | USB_TYPE_RESERVED",
    }
    ret += m[bRequestType & USB_TYPE_MASK]
    
    m = {
        USB_RECIP_DEVICE: " | USB_RECIP_DEVICE",
        USB_RECIP_INTERFACE: " | USB_RECIP_INTERFACE",
        USB_RECIP_ENDPOINT: " | USB_RECIP_ENDPOINT",
        USB_RECIP_OTHER: " | USB_RECIP_OTHER",
        USB_RECIP_PORT: " | USB_RECIP_PORT",
        USB_RECIP_RPIPE: " | USB_RECIP_RPIPE",
    }
    ret += m[bRequestType & USB_RECIP_MASK]

    return ret;


def print_urb(urb):
    print "  id: 0x%016lX" % (urb.id)
    print hex(urb.type)
    print type(urb.type)
    print "  type: %s (%c / 0x%02X)" % (urb_type2str[urb.type], urb.type, urb.type)
    #print "    dir: %s" % ('IN' if urb.type & URB_TRANSFER_IN else 'OUT',)
    print "  transfer_type: %s (0x%02X)" % (transfer2str[urb.transfer_type], urb.transfer_type )
    print "  endpoint: 0x%02X" % (urb.endpoint)
    print "  device: 0x%02X" % (urb.device)
    print "  bus_id: 0x%04X" % (urb.bus_id)
    print "  setup_request: 0x%02X" % (urb.setup_request)
    print "  data: 0x%02X" % (urb.data)
    #print "  sec: 0x%016llX" % (urb.sec)
    print "  usec: 0x%08X" % (urb.usec)
    print "  status: 0x%08X" % (urb.status)
    print "  length: 0x%08X" % (urb.length)
    print "  data_length: 0x%08X" % (urb.data_length)

def UVDHexdumpCore(*args):
    print 'hexdump broken'

class Gen:
    def __init__(self):
        self.g_cur_packet = 0
        
        
    '''
    Seems to give unexpected input vs the C API
    a1=64, 
    a2=407b162b0288ffff530280020200003cec54025300000000e91003008dffffff2800000000000000800600010000280000000000000000000002000000000000,
    a3=1392661740.2
    
    although I could unpack the data, def not how this was intended to be used and will be a lot more work. Gah!
    maybe simple C program should dump to JSON instead and leave heavy lifting to python
    '''
    def loop_cb(self, caplen, packet, ts):
        self.g_cur_packet += 1
        if self.g_cur_packet < g_min_packet or self.g_cur_packet > g_max_packet:
            # print "# Skipping packet %d" % (self.g_cur_packet)
            return
        
        '''
        struct pcap_pkthdr {
            struct timeval ts;    /* time stamp */
            bpf_u_int32 caplen;    /* length of portion present */
            bpf_u_int32 len;    /* length this packet (off wire) */
        }
        '''
        '''
        pcap_pkthdr_nt = namedtuple('pcap_pkthdr', ('ts', 'caplen', 'len'))
        def pcap_pkthdr(s):
            return  pcap_pkthdr_nt(*struct.unpack('<III', s))
        header = pcap_pkthdr(header)
        '''
        if caplen != len(packet):
            print "packet %d: malformed, caplen %d != len %d", self.g_cur_packet, caplen, len(packet)
            g_error = True
            return
        
        dbg("PACKET %u: length %u" % (self.g_cur_packet, len(packet)))
        if 0:
            print "PACKET %u: length %u" % (self.g_cur_packet, len(packet))
            UVDHexdumpCore(packet, "  ")
        
    
        '''
        typedef struct {
            uint64_t id
            uint8_t type
            uint8_t transfer_type
            uint8_t endpoint
            uint8_t device
            uint16_t bus_id
            uint8_t setup_request
            uint8_t data
            uint64_t sec
            uint32_t usec
            uint32_t status
            uint32_t length
            uint32_t data_length
            //not sure what these are...not labeled in wireshark either
            //uint8_t pad[24]
        } __attribute__((packed)) usb_urb_t
        '''
        usb_urb_nt = namedtuple('usb_urb', ('id',
                'type',
                'transfer_type',
                'endpoint',
                'device',
                'bus_id',
                'setup_request',
                'data',
                'sec',
                'usec',
                'status',
                'length',
                'data_length'))
        usb_urb_fmt = '<QBBBBHBBQIIII'
        usb_urb_sz = struct.calcsize(usb_urb_fmt)
        def usb_urb(s):
            return  usb_urb_nt(*struct.unpack(usb_urb_fmt, str(s)))
    
        # caplen is actual length, len is reported
        urb = usb_urb(packet[0:usb_urb_sz])
        dat_cur = packet[usb_urb_sz:]
        print_urb(urb)
        
        if g_verbose:
            print "Packet %d (header size: %lu)" % (self.g_cur_packet, usb_urb_sz)
            print_urb(urb)
        
        if 0:
            print "PACKET %u: URB" % (self.g_cur_packet)
            UVDHexdumpCore(urb, "  ")
        
        
        if urb.type == URB_ERROR:
            print "oh noes!"
            if (g_halt_error):
                sys.exit(1)
            
        
        # Find the matching submit request
        submit = None
        if urb.type == URB_COMPLETE:
            if not urb.id in g_pending_control:
                print "WTF?  packet %d missing control URB end.  URB ID: 0x%016lX" % (self.g_cur_packet, urb.id)
                if (g_halt_error):
                    sys.exit(1)
                
            
            submit = g_pending_control[urb.id]
            # Done with it, get rid of it
            del g_pending_control[urb.id]
            '''
            if not g_pending_control.empty():
                # print "WARNING: out of order traffic packet around %u, not too much thought put into that" % (self.g_cur_packet)
                pass
            '''
            
        if urb.transfer_type == URB_CONTROL:
            if urb.type == URB_SUBMIT:
                self.processControlSubmit(urb, dat_cur)
            elif urb.type == URB_COMPLETE:
                self.processControlComplete(submit, dat_cur)
            else:
                print "WTF?"
                if (g_halt_error):
                    sys.exit(1)
                
            
        elif urb.transfer_type == URB_BULK:
            processBulk(urb, dat_cur)
        
        
        if urb.type == URB_COMPLETE:
            # Done...release buffers if any
            #submit.free()
            pass
    
    def processControlSubmit(self, urb, dat_cur):
        pending = PendingRX()
        pending.m_urb = urb
    
        ctrl = usb_ctrlrequest(dat_cur[0:usb_ctrlrequest_sz])
        dat_cur = dat_cur[usb_ctrlrequest_sz:]
        
        if g_verbose:
            print "Packet %d control submit (control info size %lu)" % (self.g_cur_packet, sizeof(*ctrl),)
            print "    bRequestType: %s (0x%02X)" % (request_type2str(ctrl.bRequestType), ctrl.bRequestType)
            print "    bRequest: %s (0x%02X)" % (request2str(ctrl.bRequestType, ctrl.bRequest ), ctrl.bRequest)
            print "    wValue: 0x%04X" % (ctrl.wValue)
            print "    wIndex: 0x%04X" % (ctrl.wIndex)
            print "    wLength: 0x%04X" % (ctrl.wLength)
        
        if (ctrl.bRequestType & URB_TRANSFER_IN) == URB_TRANSFER_IN:
            dbg("%d: IN" % (self.g_cur_packet))
        else:
            dbg("%d: OUT" % (self.g_cur_packet))
            if (len(dat_cur) != urb.data_length):
                print "remaining bytes %d != expected payload out bytes %d" % (len(dat_cur), urb.data_length)
                UVDHexdumpCore(dat_cur, "  ")
                g_error = True
                return
            pending.m_data_out = str(dat_cur)
        
        pending.m_ctrl = ctrl
        pending.packet_number = self.g_cur_packet
        g_pending_control[urb.id] = pending


    
    def processControlCompleteIn(self, submit, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = submit.m_ctrl.wLength
        
        # Is it legal to have a 0 length control in?
        if (submit.m_ctrl.wLength):
            data_str = "buff"
            data_size = submit.m_ctrl.wLength
        elif args.ofmt == OUTPUT_LIBUSBPY:
            data_str = "\"\""
        
        
        if (keep_packet(submit)):
            printControlRequest(submit, data_str, data_size, "usb_rcvctrlpipe(%s, 0), " % (deviceStr(),) )
        
        
        # Take off the unknown struct
        if len(dat_cur) < control_rx_sz:
            print "not enough data"
            if (g_halt_error):
                sys.exit(1)
            return
        
        dat_cur = dat_cur[control_rx_sz:]
        # Now dat_cur/len(dat_cur) is the control in data payload
        
        # Verify we actually have enough / expected
        # If exact match don't care
        if (len(dat_cur) != max_payload_sz):
            if (g_allow_short and len(dat_cur) < max_payload_sz):
                print "# WARNING: shrinking response, max %u but got %u" % (max_payload_sz)
            else:
                print "expected remaining bytes %u to be the requested length %u" % (len(dat_cur), max_payload_sz)
                if (g_halt_error):
                    sys.exit(1)
                return
            
        
        
        if (submit.m_ctrl.wLength):
            if g_packet_numbers:
                packet_numbering = "packet %u/%u" % (submit.packet_number, self.g_cur_packet)
            else:
                # TODO: consider counting instead of by captured index
                packet_numbering = "packet"
            
    
            if args.ofmt == OUTPUT_LIBUSBPY:
                print "validate_read(%s, buff, \"%s\")" % (bytes2AnonArray(dat_cur, "char"),  packet_numbering )
            else:
                print "validate_read(%s, %u, buff, n_rw, \"%s\");" % (bytes2AnonArray(dat_cur, "char"), packet_numbering )
        
    
    
    def processControlCompleteOut(self, submit, dat_cur):
        data_size = 0
        data_str = "None"
        
        # print "Data out size: %u vs urb size %u" % (submit.m_data_out_size, submit.m_urb.data_length )
        if (submit.m_data_out_size):
            # Note that its the submit from earlier, not the ack that we care about
            data_str = bytes2AnonArray(submit.m_data_out, submit.m_data_out_size)
            data_size = submit.m_data_out_size
        elif args.ofmt == OUTPUT_LIBUSBPY:
            data_str = "\"\""
        
        if keep_packet(submit):
            printControlRequest(submit, data_str, data_size, "usb_sndctrlpipe(%s, 0), " % (deviceStr()) )
        
    def processControlComplete(self, submit, dat_cur):
        '''
        if (false and keep_packet(submit)):
            payload_bytes_type_t *bulk = &g_payload_bytes.bulk
            # payload_bytes_type_t *ctrl = &g_payload_bytes.ctrl
            
            print "Transer statistics")
            print "    Bulk")
            print "        In: %u (delta %u), req: %u (delta %u)",
                    bulk.in, bulk.in - bulk.in_last,
                    bulk.req_in, bulk.req_in - bulk.req_in_last
                    )
            update_delta( bulk )
            print "        Out: %u, req: %u" % (g_payload_bytes.bulk.out, g_payload_bytes.bulk.req_out)
            print "    Control")
            print "        In: %u, req: %u" % (g_payload_bytes.ctrl.in, g_payload_bytes.ctrl.req_in)
            print "        Out: %u, req: %u" % (g_payload_bytes.ctrl.out, g_payload_bytes.ctrl.req_out)
        
        
        if (!keep_packet(submit)):
            return
        
        if g_packet_numbers:
            if (args.ofmt == OUTPUT_LIBUSBPY) {
                oprintf("# Generated from packet %u/%u", submit.packet_number, self.g_cur_packet)
            else:
                oprintf("//Generated from packet %u/%u", submit.packet_number, self.g_cur_packet)
        
        if (submit.m_ctrl.bRequestType & URB_TRANSFER_IN):
            self.processControlCompleteIn(submit, dat_cur)
        else:
            self.processControlCompleteOut(submit, dat_cur)
        '''



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Replay captured USB packets')
    parser.add_argument('-r', help='range')
    parser.add_argument('-k', dest='ofmt', default='LIBUSBPY', action='store_const', const='LINUX', help='output linux kenrel')
    parser.add_argument('-l', dest='ofmt', action='store_const', const='LIBUSB', help='output libusb')
    parser.add_argument('-p', dest='ofmt', action='store_const', const='LIBUSBPY', help='output libusb python')
    
    parser.add_argument('-s', help='allow short')
    parser.add_argument('-f', help='custom call')
    parser.add_argument('-n', help='packet numbers')
    parser.add_argument('-v', action='store_true', help='verbose')

    parser.add_argument('fin', help='File name in')
    args = parser.parse_args()

    def comment(s):
        if args.ofmt == 'LIBUSBPY':
            print '# %s' % (s,)
        else:
            print '//%s' % (s,)
    
    comment("Generated by uvusbreplay %s" % (VERSION_STR,))
    comment("uvusbreplay copyright 2011 John McMaster <JohnDMcMaster@gmail.com>")
    # comment("Date: %s" % (UVDCurDateTime()))
    comment("Source data: %s" % (args.fin,))
    comment("Source range: %s - %s" % (g_min_packet, g_max_packet))
    if args.ofmt != 'LIBUSBPY':
        print "int n_rw = 0;"
        print "uint8_t buff[4096];"
    
    if args.ofmt == 'LIBUSB' and g_use_defines:
        # Libusb expects users to hard code these into address I guess
        print "# Directions"
        print "# to device"
        print "const int USB_DIR_OUT = 0;"
        print "# to host"
        print "const int URB_TRANSFER_IN = 0x80;"
        print "const int USB_TYPE_MASK = (0x03 << 5);"
        print "const int USB_TYPE_STANDARD = (0x00 << 5);"
        print "const int USB_TYPE_CLASS = (0x01 << 5);"
        print "const int USB_TYPE_VENDOR = (0x02 << 5);"
        print "const int USB_TYPE_RESERVED = (0x03 << 5);"
    
    print ""

    dbg("parsing from range %s to %s" % (g_min_packet, g_max_packet))
    
    p = pcap.pcapObject()
    p.open_offline(args.fin)
    gen = Gen()
    p.loop(-1, gen.loop_cb)
    
    if not g_pending_control.empty():
        print "WARNING: %lu pending requests" % (g_pending_control.size())
    
    # Makes copy/pasting easier in some editors...
    print ""
    print 'Done!'
    


