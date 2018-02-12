#!/usr/bin/env python

'''
uvusbreplay-py 01_prog2.cap
sudo pip install pycap
'''

import pcap
import argparse
import sys
import binascii
import struct
from collections import namedtuple
import os
import errno
import json

g_min_packet = 0
g_max_packet = float('inf')

VERSION_STR    = "0.1"
indent = ""

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
USB_TYPE_STANDARD =         (0x00 << 5) # 0x00
USB_TYPE_CLASS =            (0x01 << 5) # 0x20
USB_TYPE_VENDOR =           (0x02 << 5) # 0x40
USB_TYPE_RESERVED =         (0x03 << 5) # 0x60

USB_RECIP_MASK =            0x1f
USB_RECIP_DEVICE =          0x00
USB_RECIP_INTERFACE =       0x01
USB_RECIP_ENDPOINT =        0x02
USB_RECIP_OTHER =           0x03
# From Wireless USB 1.0
USB_RECIP_PORT =            0x04
USB_RECIP_RPIPE =           0x05


def dbg(s):
    if args and args.verbose:
        print s

def comment(s):
    if args.ofmt == 'bin':
        print '%s%s' % (indent, s)
    elif args.ofmt == 'libusbpy':
        print '%s# %s' % (indent, s)
    elif args.ofmt == 'json':
        oj['data'].append({
                'type': 'comment', 
                'v': s})
    else:
        print '%s//%s' % (indent, s)

# When we get an IN request we may process packets in between
class PendingRX:
    def __init__(self):
        # Unprocessed packet bytes
        self.raw = None
        #usb_urb_t m_urb
        self.m_urb = None
        #usb_ctrlrequest m_ctrl
        # Only applies to control requests
        self.m_ctrl = None
        self.packet_number = 0
        
        # uint8_t *m_data_out
        self.m_data_out = None

def add_bool_arg(parser, yes_arg, default=False, **kwargs):
    dashed = yes_arg.replace('--', '')
    dest = dashed.replace('-', '_')
    parser.add_argument(yes_arg, dest=dest, action='store_true', default=default, **kwargs)
    kwargs['help'] = 'Disable above'
    parser.add_argument('--no-' + dashed, dest=dest, action='store_false', **kwargs)

# Pending requests
# Typically size 0-1 but sometimes more pile up
g_pending = {}

class payload_bytes_type_t:
    def __init__(self):
        self.req_in = 0
        self.req_in_last = None
        self.in_ = 0
        self.in_last = None
    
        self.req_out = 0
        self.req_out_last = None
        self.out = 0
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
        # FIXME: what exactly are these?
        'res'))
usb_ctrlrequest_fmt = '<BBHHHH'
usb_ctrlrequest_sz = struct.calcsize(usb_ctrlrequest_fmt)
def usb_ctrlrequest(s):
    return usb_ctrlrequest_nt(*struct.unpack(usb_ctrlrequest_fmt, str(s)))


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
    
    if args.ofmt == 'bin':
        pass
    elif args.ofmt == 'libusbpy':
        #std::string bRequestStr = get_request_str( submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest )
        #std::string bRequestTypeStr = get_request_type_str(submit.m_ctrl.bRequestType)
        if submit.m_ctrl.bRequestType & URB_TRANSFER_IN:
            print "%sbuff = controlRead(0x%02X, 0x%02X, 0x%04X, 0x%04X, %u)" % (indent, submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest,
                    submit.m_ctrl.wValue, submit.m_ctrl.wIndex, data_size)
        else:
            print "%scontrolWrite(0x%02X, 0x%02X, 0x%04X, 0x%04X, %s)" % (indent, submit.m_ctrl.bRequestType, submit.m_ctrl.bRequest,
                    submit.m_ctrl.wValue, submit.m_ctrl.wIndex, data_str)
    elif args.ofmt == 'json':
        pass
    elif args.ofmt in ('libusb', 'linux'):
        timeout = ''
        out = ''
    
        out += "n_rw = "
        if args.cc:
            out += "dev_ctrl_msg("
        else:
            device_str = "g_dev"
            out += "usb_control_msg(%s, " % device_str
        
        
        if args.ofmt == 'linux':
            out += "%s", pipe_str
        
        
        bRequestStr = request_type2str[ self.submit.m_ctrl.bRequestType, self.submit.m_ctrl.bRequest ]
        bRequestTypeStr = ""
        
        if args.ofmt == 'libusb' and not args.define:
            bRequestTypeStr = "0x%02X" % self.submit.m_ctrl.bRequestType
        else:
            bRequestTypeStr = request_type2str[self.submit.m_ctrl.bRequestType]
        
        
        if args.ofmt == 'libusb':
            out += "%s, %s, " % (bRequestTypeStr, bRequestStr)
        else:
            out += "%s, %s, " % (bRequestStr, bRequestTypeStr)
        
        
        if args.cc:
            timeout = ""
        else:
            timeout = ", 500"
        
        
        out += "0x%04X, 0x%04X, %s, %u%s);" % (
                submit.m_ctrl.wValue, submit.m_ctrl.wIndex,
                data_str, data_size,
                timeout )
        print out
    else:
        raise Exception("Unknown output")

def bytes2AnonArray(bytes, byte_type = "uint8_t"):
    if args.ofmt == 'libusbpy':
        byte_str = "\""
    
        for i in xrange(len(bytes)):
            if i and i % 16 == 0:
                byte_str += '\"\n            \"'
            byte_str += "\\x%02X" % (ord(bytes[i]),)
        return byte_str + "\""
    elif args.ofmt == 'json':
        return binascii.hexlify(bytes)
    else:
        byte_str = "(%s[]){" % (byte_type,)
        pad = ""
        
        bytes = bytearray(bytes)
        for i in xrange(len(bytes)):
            if i % 16 == 0:
                pad = ""
                if i != 0:
                    byte_str += ",\n        "
                
            byte_str += pad
            byte_str += "0x%02X" % bytes[i]
            pad = ", "
        
        return byte_str + "}"


def deviceStr():
    # return "dev.udev"
    return "udev"

# Table 9-6. Standard Feature Selectors
feat_i2s = {
        # Endpoint
        0: 'ENDPOINT_HALT',
        # Device
        1: 'DEVICE_REMOTE_WAKEUP',
        # Device
        2: 'TEST_MODE',
        }

setup_reqs = [
            # reply type
            #"GET_STATUS",
            "CLEAR_FEATURE",
            "SET_FEATURE",
            "SET_ADDRESS",
            "GET_DESCRIPTOR",
            "SET_DESCRIPTOR",
            "GET_CONFIGURATION",
            "SET_CONFIGURATION",
            "SET_INTERFACE",
            "GET_INTERFACE",
            "CLEAR_FEATURE",
            "SYNCH_FRAME",  
            ]

def req2s(ctrl):
    m = {
        USB_TYPE_STANDARD: {
            USB_REQ_GET_STATUS:         "GET_STATUS",
            USB_REQ_CLEAR_FEATURE:      "CLEAR_FEATURE",
            USB_REQ_SET_FEATURE:        "SET_FEATURE",
            USB_REQ_SET_ADDRESS:        "SET_ADDRESS",
            USB_REQ_GET_DESCRIPTOR:     "GET_DESCRIPTOR",
            USB_REQ_SET_DESCRIPTOR:     "SET_DESCRIPTOR",
            USB_REQ_GET_CONFIGURATION:  "GET_CONFIGURATION",
            USB_REQ_SET_CONFIGURATION:  "SET_CONFIGURATION",
            USB_REQ_SET_INTERFACE:      "SET_INTERFACE",
        },
        USB_TYPE_CLASS: {
            USB_REQ_GET_STATUS:         "GET_STATUS",
            USB_REQ_CLEAR_FEATURE:      "CLEAR_FEATURE",
            USB_REQ_SET_FEATURE:        "SET_FEATURE",
            USB_REQ_GET_INTERFACE:      "GET_INTERFACE",
        },
        USB_TYPE_VENDOR: {
            USB_REQ_GET_STATUS:         "GET_STATUS",
            USB_REQ_SET_FEATURE:        "SET_FEATURE",
            USB_REQ_CLEAR_FEATURE:      "CLEAR_FEATURE",
            USB_REQ_SYNCH_FRAME:        "SYNCH_FRAME",  
        },
    }
    if args.fx2:
        m[USB_TYPE_VENDOR].update({
            0xA0:         "FX2_REG_W",
        })
    
    reqType = ctrl.bRequestType & USB_TYPE_MASK
    n = m.get(reqType, None)
    if n is None or not ctrl.bRequest in n:
        return None
    reqs = n[ctrl.bRequest]
    return reqs

def req_comment(ctrl, dat):
    # Table 9-3. Standard Device Requests
    reqs = req2s(ctrl)
    ret = '%s (0x%02X)' % (reqs, ctrl.bRequest)
    if reqs == 'SET_ADDRESS':
        ret += ': 0x%02x/%d' % (ctrl.wValue, ctrl.wValue)
    elif reqs == 'SET_FEATURE' or reqs == 'CLEAR_FEATURE':
        ret += ': 0x%02X (%s)' % (ctrl.wValue, feat_i2s.get(ctrl.wValue, 'unknown'))
    elif reqs == 'FX2_REG_W':
        addr = ctrl.wValue
        reg2s = {
                0xE600: 'CPUCS',
                }
        reg = reg2s.get(addr, None)
        
        ret += ': addr=0x%04X' % (ctrl.wValue)
        if reg:
            ret += ' (%s)' % (reg,)
        elif addr < 0x1000:
            ret += ' (FW load)'
        
        if len(dat) == 1:
            dat = ord(dat)
            if reg == 'CPUCS':
                if dat & 1 == 1:
                    ret += ', reset: hold'
                else:
                    ret += ', reset: release'
    comment(ret)


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
    print "URB id: 0x%016lX" % (urb.id)
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

def hexdump(*args):
    try:
        from uvscada.util import hexdump
        hexdump(*args)
    except:
        comment('hexdump broken')

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
    //These form the URB setup for control transfers and are techincally part of the URB
    //uint8_t pad[24]
} __attribute__((packed)) usb_urb_t
'''
usb_urb_nt = namedtuple('usb_urb', (
        'id',
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
        
        # Control: requested data length
        # Complete: identical to data_length?
        'length',
        # How much data is attached to this message
        'data_length',
        # Main use is URB setup for control requests, not sure if thats universal?
        # TODO: check how these are used in bulk requests
        # If it is the same, they should be merged into this structure
        'ctrlrequest',))
usb_urb_fmt = ('<'
        'Q' # id
        'B'
        'B'
        'B'
        
        'B' # device
        'H'
        'B'
        'B'
        
        'Q' # sec
        'I'
        'i'
        
        'I' # length
        'I'
        '24s')
usb_urb_sz = struct.calcsize(usb_urb_fmt)
def usb_urb(s):
    return  usb_urb_nt(*struct.unpack(usb_urb_fmt, str(s)))

class Gen:
    def __init__(self):
        self.g_cur_packet = 0
        self.rel_pkt = 0
        self.previous_urb_complete_kept = None
        self.pending_complete = {}
        
    def loop_cb(self, caplen, packet, ts):
        self.g_cur_packet += 1
        if self.g_cur_packet < g_min_packet or self.g_cur_packet > g_max_packet:
            # print "# Skipping packet %d" % (self.g_cur_packet)
            return
        if args.verbose:
            print
            print
            print
            print 'PACKET %s' % (self.g_cur_packet,)
        
        if caplen != len(packet):
            print "packet %s: malformed, caplen %d != len %d", self.pktn_str(), caplen, len(packet)
            return
        if args.verbose:
            print 'Len: %d' % len(packet)
        
        dbg("Length %u" % (len(packet),))
        if len(packet) < usb_urb_sz:
            hexdump(packet)
            raise ValueError("Packet size %d is not min size %d" % (len(packet), usb_urb_sz))
    
        # caplen is actual length, len is reported
        self.urb_raw = packet
        self.urb = usb_urb(packet[0:usb_urb_sz])
        dat_cur = packet[usb_urb_sz:]
        
        # Main packet filtering
        # Drop if not specified device
        if args.device is not None and self.urb.device != args.device:
            return
        # Drop if is generic device management traffic
        if not args.setup and self.urb.transfer_type == URB_CONTROL:
            ctrl = usb_ctrlrequest(self.urb.ctrlrequest[0:usb_ctrlrequest_sz])
            reqst = req2s(ctrl)
            if reqst in setup_reqs or reqst == "GET_STATUS" and self.urb.type == URB_SUBMIT:
                g_pending[self.urb.id] = None
                self.submit = None
                self.urb = None
                return
        self.rel_pkt += 1
        
        if args.verbose:
            print "Header size: %lu" % (usb_urb_sz,)
            print_urb(urb)
        
        if self.urb.type == URB_ERROR:
            print "oh noes!"
            if args.halt:
                sys.exit(1)
        
        if self.urb.type == URB_COMPLETE:
            if args.verbose:
                print 'Pending (%d):' % (len(g_pending),)
                for k in g_pending:
                    print '  %s' % (k,)
            # for some reason usbmon will occasionally give packets out of order
            if not self.urb.id in g_pending:
                #raise Exception("Packet %s missing submit.  URB ID: 0x%016lX" % (self.pktn_str(), self.urb.id))
                comment("WARNING: Packet %s missing submit.  URB ID: 0x%016lX" % (self.pktn_str(), self.urb.id))
                self.pending_complete[self.urb.id] = (self.urb, dat_cur)
            else:
                self.process_complete(dat_cur)
                
        elif self.urb.type == URB_SUBMIT:
            # Find the matching submit request
            if self.urb.transfer_type == URB_CONTROL:
                self.processControlSubmit(dat_cur)
            elif self.urb.transfer_type == URB_BULK:
                self.processBulkSubmit(dat_cur)
            elif self.urb.transfer_type == URB_INTERRUPT:
                pending = PendingRX()
                pending.raw = self.urb_raw
                pending.m_urb = self.urb
                pending.packet_number = self.pktn_str()
                if args.verbose:
                    print 'Added pending bulk URB %s' % self.urb.id
                g_pending[self.urb.id] = pending
            
            if self.urb.id in self.pending_complete:
                # oh snap solved a temporal anomaly
                urb_submit = self.urb
                (urb_complete, dat_cur) = self.pending_complete[self.urb.id]
                del self.pending_complete[self.urb.id]
                self.urb = urb_complete
                self.process_complete(dat_cur)
                
        self.submit = None
        self.urb = None

    def pktn_str(self):
        if args.rel_pkt:
            return self.rel_pkt
        else:
            return self.g_cur_packet

    def process_complete(self, dat_cur):
        self.submit = g_pending[self.urb.id]
        # Done with it, get rid of it
        del g_pending[self.urb.id]

        # Discarded?
        if self.submit is None:
            return

        if args.ofmt in ('LINUX', 'LIBUSB'):
            print
        self.packnum()

        if self.previous_urb_complete_kept is not None:
            '''
            For bulk packets this can get tricky
            The intention was mostly for control packets where timing might be more critical
            '''
            if args.sleep and args.ofmt == 'libusbpy':
                prev = self.previous_urb_complete_kept
                
                # mind order of operations here...was having round off issues
                ds = self.submit.m_urb.sec - prev.sec
                dt = ds + self.submit.m_urb.usec/1.e6 - prev.usec/1.e6
                if dt < -1.e-6:
                    # stupid reversed packets
                    if 0:
                        print 'prev sec: %s' % prev.sec
                        print 'prev usec: %s' % prev.usec
                        print 'this sec: %s' % self.submit.m_urb.sec
                        print 'this usec: %s' % self.submit.m_urb.usec
                        raise Exception("bad calc: %s" % dt)
                elif dt >= 0.001:
                    print '%stime.sleep(%.3f)' % (indent, dt)
        EREMOTEIO = -121
        if self.urb.status != 0 and not (not args.remoteio and self.urb.status == EREMOTEIO):
            print '%s# WARNING: complete code %s (%s)' % (indent, self.urb.status,  errno.errorcode.get(-self.urb.status, "unknown"))
        
        self.previous_urb_complete_kept = self.urb

        # Find the matching submit request
        if self.urb.transfer_type == URB_CONTROL:
            self.processControlComplete(dat_cur)
        elif self.urb.transfer_type == URB_BULK:
            self.processBulkComplete(dat_cur)
        elif self.urb.transfer_type == URB_INTERRUPT:
            self.processInterruptComplete(dat_cur)
    
    def processControlSubmit(self, dat_cur):
        pending = PendingRX()
        pending.raw = self.urb_raw
        pending.m_urb = self.urb
    
        if args.verbose:
            print 'Remaining data: %d' % (len(dat_cur))
            print 'ctrlrequest: %d' % (len(urb.ctrlrequest))
        ctrl = usb_ctrlrequest(self.urb.ctrlrequest[0:usb_ctrlrequest_sz])
        
        if args.verbose:
            print "Packet %s control submit (control info size %lu)" % (self.pktn_str(), 666)
            print "    bRequestType: %s (0x%02X)" % (request_type2str(ctrl.bRequestType), ctrl.bRequestType)
            #print "    bRequest: %s (0x%02X)" % (request2str(ctrl), ctrl.bRequest)
            print "    wValue: 0x%04X" % (ctrl.wValue)
            print "    wIndex: 0x%04X" % (ctrl.wIndex)
            print "    wLength: 0x%04X" % (ctrl.wLength)
        
        if (ctrl.bRequestType & URB_TRANSFER_IN) == URB_TRANSFER_IN:
            dbg("%d: IN" % (self.g_cur_packet))
        else:
            dbg("%d: OUT" % (self.g_cur_packet))
            if len(dat_cur) != self.urb.data_length:
                comment("WARNING: remaining bytes %d != expected payload out bytes %d" % (len(dat_cur), self.urb.data_length))
                hexdump(dat_cur, "  ")
                #raise Exception('See above')
            pending.m_data_out = str(dat_cur)
        
        pending.m_ctrl = ctrl
        pending.packet_number = self.pktn_str()
        if args.verbose:
            print 'Added pending control URB %s' % self.urb.id
        g_pending[self.urb.id] = pending


    def processControlCompleteIn(self, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = self.submit.m_ctrl.wLength
        
        # Is it legal to have a 0 length control in?
        if self.submit.m_ctrl.wLength:
            data_str = "buff"
            data_size = self.submit.m_ctrl.wLength
        elif args.ofmt == 'libusbpy':
            data_str = "\"\""
        
        printControlRequest(self.submit, data_str, data_size, "usb_rcvctrlpipe(%s, 0), " % (deviceStr(),) )
        
        # Verify we actually have enough / expected
        # If exact match don't care
        if len(dat_cur) != max_payload_sz:
            if len(dat_cur) < max_payload_sz:
                comment("NOTE:: req max %u but got %u" % (max_payload_sz, len(dat_cur)))
            else:
                raise Exception('invalid response')
        
        if args.ofmt == 'json':
            oj['data'].append({
                    'type': 'controlRead',
                    'reqt': self.submit.m_ctrl.bRequestType, 
                    'req': self.submit.m_ctrl.bRequest,
                    'val': self.submit.m_ctrl.wValue, 
                    'ind': self.submit.m_ctrl.wIndex, 
                    'len': self.submit.m_ctrl.wLength,
                    'data': bytes2AnonArray(dat_cur),
                    'packn': self.packnumt(),
                    })
        
        
        if self.submit.m_ctrl.wLength:
            if args.packet_numbers:
                packet_numbering = "packet %s/%s" % (self.submit.packet_number, self.pktn_str())
            else:
                # TODO: consider counting instead of by captured index
                packet_numbering = "packet"
            
    
            if args.ofmt == 'libusbpy':
                print "%svalidate_read(%s, buff, \"%s\")" % (indent, bytes2AnonArray(dat_cur, "char"),  packet_numbering )
            elif args.ofmt in ('LINUX', 'LIBUSB'):
                print "%svalidate_read(%s, %u, buff, n_rw, \"%s\");" % (indent, bytes2AnonArray(dat_cur, "char"), packet_numbering )
    
    def processControlCompleteOut(self, dat_cur):
        data_size = 0
        data_str = "None"
        
        #print 'Control out w/ len %d' % len(submit.m_data_out)
        
        # print "Data out size: %u vs urb size %u" % (submit.m_data_out_size, submit.m_urb.data_length )
        if len(self.submit.m_data_out):
            # Note that its the submit from earlier, not the ack that we care about
            data_str = bytes2AnonArray(self.submit.m_data_out)
            data_size = len(self.submit.m_data_out)
        elif args.ofmt == 'libusbpy':
            data_str = "\"\""
        
        printControlRequest(self.submit, data_str, data_size, "usb_sndctrlpipe(%s, 0), " % (deviceStr()) )
        
        if args.ofmt == 'json':
            oj['data'].append({
                    'type': 'controlWrite',
                    'reqt': self.submit.m_ctrl.bRequestType, 
                    'req': self.submit.m_ctrl.bRequest,
                    'val': self.submit.m_ctrl.wValue, 
                    'ind': self.submit.m_ctrl.wIndex, 
                    'data': bytes2AnonArray(self.submit.m_data_out),
                    'packn': self.packnumt(),
                    })
        
    def processControlComplete(self, dat_cur):
        if args.comment:
            req_comment(self.submit.m_ctrl, self.submit.m_data_out)
        
        if self.submit.m_ctrl.bRequestType & URB_TRANSFER_IN:
            self.processControlCompleteIn(dat_cur)
        else:
            self.processControlCompleteOut(dat_cur)

    def print_stat(self):
        bulk = g_payload_bytes.bulk
        # payload_bytes_type_t *ctrl = &g_payload_bytes.ctrl
        
        print "Transer statistics"
        print "    Bulk"
        print "        In: %u (delta %u), req: %u (delta %u)" % (
                bulk.in_, bulk.in_ - bulk.in_last,
                bulk.req_in, bulk.req_in - bulk.req_in_last
                )
        update_delta( bulk )
        print "        Out: %u, req: %u" % (g_payload_bytes.bulk.out, g_payload_bytes.bulk.req_out)
        print "    Control"
        print "        In: %u, req: %u" % (g_payload_bytes.ctrl.in_, g_payload_bytes.ctrl.req_in)
        print "        Out: %u, req: %u" % (g_payload_bytes.ctrl.out, g_payload_bytes.ctrl.req_out)

    def packnum(self):
        '''
        Originally I didn't print anything but found that it was better to keep the line numbers the same
        so that I could diff and then easier back annotate with packet numbers
        '''
        if args.packet_numbers:
            comment("Generated from packet %s/%s" % (self.submit.packet_number, self.pktn_str()))
        else:
            comment("Generated from packet %s/%s" % (None, None))

    def packnumt(self):
        if args.packet_numbers:
            return (self.submit.packet_number, self.pktn_str())
        else:
            return (None, None)
        
    def processBulkSubmit(self, dat_cur):
        if self.urb.type & USB_DIR_IN:
            g_payload_bytes.bulk.req_in += self.urb.length
        else:
            g_payload_bytes.bulk.req_out += self.urb.length        

        pending = PendingRX()
        pending.raw = self.urb_raw
        pending.m_urb = self.urb
    
        if args.verbose:
            print 'Remaining data: %d' % (len(dat_cur))
        
        #if args.verbose:
        #    print "Packet %d bulk submit (control info size %lu)" % (self.pktn_str(), 666)
        
        
        if self.urb.endpoint & URB_TRANSFER_IN:
            dbg("%d: IN" % (self.g_cur_packet))
        else:
            dbg("%d: OUT" % (self.g_cur_packet))
            if len(dat_cur) != self.urb.data_length:
                comment("WARNING: remaining bytes %d != expected payload out bytes %d" % (len(dat_cur), self.urb.data_length))
                hexdump(dat_cur, "  ")
                #raise Exception('See above')
            pending.m_data_out = str(dat_cur)

        
        pending.packet_number = self.pktn_str()
        if args.verbose:
            print 'Added pending bulk URB %s' % self.urb.id
        g_pending[self.urb.id] = pending


    def processBulkCompleteIn(self, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = self.submit.m_urb.length
        
        # FIXME: this is a messy conversion artfact from the C code
        # Is it legal to have a 0 length bulk in?
        if max_payload_sz:
            data_str = "buff"
            data_size = max_payload_sz
        elif args.ofmt == 'libusbpy':
            data_str = "\"\""
        
        
        
        if args.bulk_dir:
            pass
        elif args.ofmt == 'libusbpy':
            # def bulkRead(self, endpoint, length, timeout=0):
            print "%sbuff = bulkRead(0x%02X, 0x%04X)" % (indent, self.submit.m_urb.endpoint, data_size)
        elif args.ofmt == 'json':
            # output below
            oj['data'].append({
                    'type': 'bulkRead',
                    'endp': self.submit.m_urb.endpoint, 
                    'len': data_size,
                    'data': bytes2AnonArray(dat_cur),
                    'packn': self.packnumt(),
                    })
        else:
            '''
            int LIBUSB_CALL libusb_bulk_transfer(libusb_device_handle *dev_handle,
                unsigned char endpoint, unsigned char *data, int length,
                int *actual_length, unsigned int timeout);
            '''
            raise Exception('FIXME')
        
        # Verify we actually have enough / expected
        # If exact match don't care
        if len(dat_cur) != max_payload_sz:
            if len(dat_cur) < max_payload_sz:
                comment("NOTE:: req max %u but got %u" % (max_payload_sz, len(dat_cur)))
            else:
                raise Exception('invalid response')
        
        if max_payload_sz:
            if args.packet_numbers:
                packet_numbering = "packet %s/%s" % (self.submit.packet_number, self.pktn_str())
            else:
                # TODO: consider counting instead of by captured index
                packet_numbering = "packet"
            
    
            if args.bulk_dir:
                fn = os.path.join(args.bulk_dir, 'pkt%06d_bulk_in.bin' % self.pktn_str())
                print 'Saving %s, len %d' % (fn, len(dat_cur))
                open(fn, 'w').write(dat_cur)
            elif args.ofmt == 'libusbpy':
                print "%svalidate_read(%s, buff, \"%s\")" % (indent, bytes2AnonArray(dat_cur, "char"),  packet_numbering )
            elif args.ofmt in ('LINUX', 'LIBUSB'):
                print "%svalidate_read(%s, %u, buff, n_rw, \"%s\");" % (indent, bytes2AnonArray(dat_cur, "char"), packet_numbering )
        
    
    
    def processBulkCompleteOut(self, dat_cur):
        data_size = 0
        
        # print "Data out size: %u vs urb size %u" % (submit.m_data_out_size, self.submit.m_urb.data_length )
        if args.ofmt == 'libusbpy': 
            # Note that its the submit from earlier, not the ack that we care about
            data_str = bytes2AnonArray(self.submit.m_data_out)
            # def bulkWrite(self, endpoint, data, timeout=0):
            print "%sbulkWrite(0x%02X, %s)" % (indent, self.submit.m_urb.endpoint, data_str)
        elif args.ofmt == 'json':
            # output below
            oj['data'].append({
                    'type': 'bulkWrite',
                    'endp': self.submit.m_urb.endpoint, 
                    'data': bytes2AnonArray(self.submit.m_data_out),
                    'packn': self.packnumt(),
                    })
        else:
            '''
            int LIBUSB_CALL libusb_bulk_transfer(libusb_device_handle *dev_handle,
                unsigned char endpoint, unsigned char *data, int length,
                int *actual_length, unsigned int timeout);
            '''
            raise Exception('FIXME')

    def processBulkComplete(self, dat_cur):
        if self.urb.endpoint & USB_DIR_IN:
            g_payload_bytes.bulk.in_ += self.urb.data_length
            self.processBulkCompleteIn(dat_cur)
        else:
            g_payload_bytes.bulk.out += self.urb.data_length
            self.processBulkCompleteOut(dat_cur)
    
    def processInterruptComplete(self, dat_cur):
        if args.ofmt in ('LINUX', 'LIBUSB'):
            print
        print '%s# WARNING: omitting interrupt' % (indent,)

args = None
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Replay captured USB packets')
    parser.add_argument('--range', '-r', help='inclusive range like 123:456')
    parser.add_argument('-k', dest='ofmt', default='libusbpy', action='store_const', const='linux', help='output linux kenrel')
    parser.add_argument('-l', dest='ofmt', action='store_const', const='libusb', help='output libusb')
    parser.add_argument('-p', dest='ofmt', action='store_const', const='libusbpy', help='output libusb python')
    parser.add_argument('-j', dest='ofmt', action='store_const', const='json', help='output json')
    parser.add_argument('-s', help='allow short')
    parser.add_argument('-f', help='custom call')
    add_bool_arg(parser, '--packet-numbers', default=True, help='print packet numbers') 
    parser.add_argument('--bulk-dir', help='bulk data .bin dir')
    parser.add_argument('--verbose', '-v', action='store_true', help='verbose')
    add_bool_arg(parser, '--sleep', default=False, help='Insert sleep statements between packets to keep original timing')
    add_bool_arg(parser, '--comment', default=False, help='General comments')
    add_bool_arg(parser, '--fx2', default=False, help='FX2 comments')
    add_bool_arg(parser, '--define', default=False, help='Use defines instead of raw numbers')
    add_bool_arg(parser, '--halt', default=True, help='Halt on errors')
    add_bool_arg(parser, '--cc', default=False, help='Custom call output')
    parser.add_argument('--device', type=int, default=None, help='Only keep packets for given device')
    add_bool_arg(parser, '--rel-pkt', default=False, help='Only count kept packets')
    # http://sourceforge.net/p/libusb/mailman/message/25635949/
    add_bool_arg(parser, '--remoteio', default=False, help='Warn on -EREMOTEIO resubmit (default: ignore)')
    add_bool_arg(parser, '--setup', default=False, help='Emit initialization packets like CLEAR_FEATURE, SET_FEATURE')

    parser.add_argument('fin', help='File name in')
    args = parser.parse_args()

    if args.range:
        (g_min_packet, g_max_packet) = args.range.split(':')
        if len(g_min_packet) == 0:
            g_min_packet = 0
        else:
            g_min_packet = int(g_min_packet, 0)
        if len(g_max_packet) == 0:
            g_max_packet = float('inf')
        else:
            g_max_packet = int(g_max_packet, 0)
    
    if args.bulk_dir:
        args.ofmt = 'bin'
        os.mkdir(args.bulk_dir)

    oj = {
        'data': [],
        'fn': args.fin,
        'args': sys.argv,
    }
    

    comment("Generated by uvusbreplay %s" % (VERSION_STR,))
    comment("uvusbreplay copyright 2011 John McMaster <JohnDMcMaster@gmail.com>")
    # comment("Date: %s" % (UVDCurDateTime()))
    comment("cmd: %s" % (' '.join(sys.argv),))
    if args.ofmt == 'libusbpy':
        print '''        
import binascii
import time
import usb1

def validate_read(expected, actual, msg):
    if expected != actual:
        print 'Failed %s' % msg
        print '  Expected; %s' % binascii.hexlify(expected,)
        print '  Actual:   %s' % binascii.hexlify(actual,)
        #raise Exception('failed validate: %s' % msg)

'''
    if args.ofmt == 'LIBUSBPY':
        print 'def replay(dev):'
        indent = "    "
        print '''\
    def bulkRead(endpoint, length, timeout=None):
        if timeout is None:
            timeout = 1000
        return dev.bulkRead(endpoint, length, timeout=timeout)

    def bulkWrite(endpoint, data, timeout=None):
        if timeout is None:
            timeout = 1000
        dev.bulkWrite(endpoint, data, timeout=timeout)
    
    def controlRead(request_type, request, value, index, length,
                    timeout=None):
        if timeout is None:
            timeout = 1000
        return dev.controlRead(request_type, request, value, index, length,
                    timeout=timeout)

    def controlWrite(request_type, request, value, index, data,
                     timeout=None):
        if timeout is None:
            timeout = 1000
        dev.controlWrite(request_type, request, value, index, data,
                     timeout=timeout)
'''

    if args.ofmt in ('LINUX', 'LIBUSB'):
        print "int n_rw = 0;"
        print "uint8_t buff[4096];"
    
    if args.ofmt == 'LIBUSB' and args.define:
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
    
    if len(g_pending) != 0:
        comment("WARNING: %lu pending requests" % (len(g_pending)))


    if args.ofmt == 'libusbpy':
        print '''
def open_dev(usbcontext=None):
    if usbcontext is None:
        usbcontext = usb1.USBContext()
    
    print 'Scanning for devices...'
    for udev in usbcontext.getDeviceList(skip_on_error=True):
        vid = udev.getVendorID()
        pid = udev.getProductID()
        if (vid, pid) == (0x14b9, 0x0001):
            print
            print
            print 'Found device'
            print 'Bus %03i Device %03i: ID %04x:%04x' % (
                udev.getBusNumber(),
                udev.getDeviceAddress(),
                vid,
                pid)
            return udev.open()
    raise Exception("Failed to find a device")

if __name__ == "__main__":
    import argparse 
    
    parser = argparse.ArgumentParser(description='Replay captured USB packets')
    args = parser.parse_args()

    usbcontext = usb1.USBContext()
    dev = open_dev(usbcontext)
    dev.claimInterface(0)
    dev.resetDevice()
    replay(dev)

'''

    if args.ofmt == 'json':
        print json.dumps(oj, sort_keys=True, indent=4, separators=(',', ': '))
