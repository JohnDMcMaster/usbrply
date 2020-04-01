#!/usr/bin/env python

'''
Windows is quirky
http://desowin.org/usbpcap/capture_limitations.html

Control packets
-What are the status packets used for?
-Control write has the request on the response packet

Bulk packets
-Only one packet for both request and response
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
from lib2to3.fixes.fix_metaclass import FixMetaclass

args = None

g_min_packet = 0
g_max_packet = float('inf')

VERSION_STR    = "0.1"
indent = ""

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

# Windows transfer stages
# Usb function: URB_FUNCTION_VENDOR_DEVICE (0x17)
XFER_SETUP = 0
# Usb function: URB_FUNCTION_CONTROL_TRANSFER (0x08)
XFER_DATA = 1
# Usb function: URB_FUNCTION_CONTROL_TRANSFER (0x08)
XFER_STATUS = 2

USBD_STATUS_SUCCESS = 0

# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540409(v=vs.85).aspx
URB_FUNCTION_CONTROL_TRANSFER = 0x08
URB_FUNCTION_VENDOR_DEVICE = 0x17

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

def transfer2str_safe(t):
    return transfer2str.get(t, "UNKNOWN_%02x" % t)


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


'''
struct usb_ctrlrequest {
    __u8 bRequestType;
    __u8 bRequest;
    __le16 wValue;
    __le16 wIndex;
    __le16 wLength;
} __attribute__ ((packed));
'''
usb_ctrlrequest_nt = namedtuple('usb_ctrlrequest_win', ('bRequestType',
        'bRequest',
        'wValue',
        'wIndex',
        'wLength',
        ))
usb_ctrlrequest_fmt = '<BBHHH'
usb_ctrlrequest_sz = struct.calcsize(usb_ctrlrequest_fmt)
def usb_ctrlrequest(s):
    return usb_ctrlrequest_nt(*struct.unpack(usb_ctrlrequest_fmt, str(s)))

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
usb_urb_lin_nt = namedtuple('usb_urb_lin', (
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
usb_urb_lin_fmt = ('<'
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

'''
IRP: I/O request packet
https://msdn.microsoft.com/en-us/library/windows/hardware/ff550694(v=vs.85).aspx
'''
# Header
# Packet may have additional data
usb_urb_win_nt = namedtuple('usb_urb_win', (
        # Length of entire packet entry including htis header and additional pkt_len data
        'pcap_hdr_len',
        # IRP ID
        # buffer ID or something like that
        # it is not a unique packet ID
        # but can be used to match up submit and response
        'id',
        # IRP_USBD_STATUS
        'irp_status',
        # USB Function
        'usb_func',
        # IRP Information
        # Ex: Direction: PDO => FDO
        'irp_info',
        # USB port
        # Ex: 3
        'bus_id',
        # USB device on that port
        # Ex: 16
        'device',
        # Which endpoint on that bus
        # Ex: 0x80 (0 in)
        'endpoint',
        # Ex: URB_CONTROL
        'transfer_type',
        # Length of data beyond header
        'data_length',
        ))
usb_urb_win_fmt = ('<'
        'H' # pcap_hdr_len
        'Q' # irp_id
        'I' # irp_status
        'H' # usb_func
        'B' # irp_info
        'H' # bus_id
        'H' # device
        'B' # endpoint
        'B' # transfer_type
        'I' # data_length
        )

#print 'WARNING: experimental windows mode activated'
usb_urb_nt = usb_urb_win_nt
usb_urb_fmt = usb_urb_win_fmt

usb_urb_sz = struct.calcsize(usb_urb_fmt)
def usb_urb(s):
    return  usb_urb_nt(*struct.unpack(usb_urb_fmt, str(s)))



def dbg(s):
    if args and args.verbose:
        print(s)

def comment(s):
    oj['data'].append({
            'type': 'comment', 
            'v': s})

def warning(s):
    comment('WARNING: %s' % s)

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

def bytes2AnonArray(bytes, byte_type = "uint8_t"):
    return binascii.hexlify(bytes)

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

# FX2 regs: http://www.keil.com/dd/docs/datashts/cypress/fx2_trm.pdf
# FX2LP regs: http://www.cypress.com/file/126446/download
def req_comment(ctrl, dat):
    # Table 9-3. Standard Device Requests
    reqs = req2s(ctrl)
    if not reqs:
        return
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

        # 5.4 FX2 Memory Maps
        # Appendix C
        # FX2 Register Summary
        ret += ': addr=0x%04X' % (ctrl.wValue)
        if reg:
            ret += ' (%s)' % (reg,)
        elif addr < 0x1000:
            ret += ' (FW load)'
        # FX2: 8K of on-chip RAM (the "Main RAM") at addresses 0x0000-0x1FFF
        # FX2LP: 16K
        elif 0x0000 <= addr <= 0x3FFF:
            ret += ' (main RAM addr=0x%04X)' % addr
        # 512 bytes of on-chip RAM (the "Scratch RAM") at addresses 0xE000-0xE1FFF
        elif 0xE000 <= addr <= 0xE1FF:
            ret += ' (scratch RAM)'
        # The CPU communicates with the SIE using a set of registers occupying on-chip RAM addresses 0xE600-0xE6FF"
        elif 0xE600 <= addr <= 0xE6FF:
            ret += ' (unknown reg)'
        # per memory map: 7.5KB of USB regs and 4K EP buffers
        elif 0xE200 <= addr <= 0xFFFF:
            ret += ' (unknown misc)'
        else:
            ret += ' (unknown)'

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
    print("URB id: 0x%016lX" % (urb.id))
    print("  type: %s (%c / 0x%02X)" % (urb_type2str[urb.type], urb.type, urb.type))
    #print("    dir: %s" % ('IN' if urb.type & URB_TRANSFER_IN else 'OUT',))
    print("  transfer_type: %s (0x%02X)" % (transfer2str_safe(urb.transfer_type), urb.transfer_type ))
    print("  endpoint: 0x%02X" % (urb.endpoint))
    print("  device: 0x%02X" % (urb.device))
    print("  bus_id: 0x%04X" % (urb.bus_id))
    print("  setup_request: 0x%02X" % (urb.setup_request))
    print("  data: 0x%02X" % (urb.data))
    #print("  sec: 0x%016llX" % (urb.sec))
    print("  usec: 0x%08X" % (urb.usec))
    print("  status: 0x%08X" % (urb.status))
    print("  length: 0x%08X" % (urb.length))
    print("  data_length: 0x%08X" % (urb.data_length))

def hexdump(*args):
    try:
        from uvscada.util import hexdump
        hexdump(*args)
    except:
        comment('hexdump broken')

def urb_error(urb):
    return urb.irp_status != USBD_STATUS_SUCCESS

def is_urb_submit(urb):
    return urb.usb_func == URB_FUNCTION_VENDOR_DEVICE

def is_urb_complete(urb):
    return urb.usb_func == URB_FUNCTION_CONTROL_TRANSFER

def printv(s):
    if args.verbose:
        print(s)

def urb_id_str(urb_id):
    # return binascii.hexlify(urb_id)
    return '0x%X' % urb_id

def update_args(args_):
    global args
    args = args_

class Gen:
    def __init__(self, args):
        update_args(args)

        self.g_cur_packet = 0
        self.rel_pkt = 0
        self.previous_urb_complete_kept = None
        self.pending_complete = {}
        self.errors = 0
        
    def loop_cb(self, caplen, packet, ts):
        try:
            self.g_cur_packet += 1
            if self.g_cur_packet < g_min_packet or self.g_cur_packet > g_max_packet:
                # print("# Skipping packet %d" % (self.g_cur_packet))
                return
            if args.verbose:
                print()
                print()
                print()
                print('PACKET %s' % (self.g_cur_packet,))

            if caplen != len(packet):
                print("packet %s: malformed, caplen %d != len %d", self.pktn_str(), caplen, len(packet))
                return
            if args.verbose:
                print('Len: %d' % len(packet))
                hexdump(packet)
                #print(ts)
                print('Pending: %d' % len(g_pending))
            
            dbg("Length %u" % (len(packet),))
            if len(packet) < usb_urb_sz:
                msg = "Packet %s: size %d is not min size %d" % (self.pktn_str(), len(packet), usb_urb_sz)
                self.errors += 1
                if args.halt:
                    hexdump(packet)
                    raise ValueError(msg)
                if args.verbose:
                    print(msg)
                    hexdump(packet)
                return
    
            # caplen is actual length, len is reported
            self.urb_raw = packet
            self.urb = usb_urb(packet[0:usb_urb_sz])
            dat_cur = packet[usb_urb_sz:]
    
            printv('ID %s' % (urb_id_str(self.urb.id),))
    
            # Main packet filtering
            # Drop if not specified device
            #print(self.pktn_str(), self.urb.device, args.device)
            if args.device is not None and self.urb.device != args.device:
                return
    
            # FIXME: hack to only process control for now
            if self.urb.transfer_type != URB_CONTROL:
                warning('packet %s: drop packet type %s' % (self.pktn_str(), transfer2str_safe(self.urb.transfer_type)))
                return
    
            # Drop status packets
            if self.urb.transfer_type == URB_CONTROL:
                # Control transfer stage
                # 1: data
                # 2: status
                # 'xfer_stage',
                xfer_stage = ord(dat_cur[0])
                #print('xfer_stage: %d' % xfer_stage)
                if xfer_stage == XFER_STATUS:
                    printv('drop xfer_status')
                    return
    
            # Drop if generic device management traffic
            if not args.setup and self.urb.transfer_type == URB_CONTROL:
                def skip():
                    # FIXME: broken
                    # Doesn't seem to be hurting downstream tools, don't worry about for now
                    return False

                    # Was the submit marked for ignore?
                    # For some reason these don't have status packets
                    if self.urb.id in g_pending and g_pending[self.urb.id] is None:
                        return True
                    # Submit then
                    # Skip xfer_stage
                    ctrl = usb_ctrlrequest(dat_cur[1:])
                    reqst = req2s(ctrl)
                    return reqst in setup_reqs or reqst == "GET_STATUS" and self.urb.type == URB_SUBMIT

                if skip():
                    print('Drop setup packet %s' % self.pktn_str())
                    g_pending[self.urb.id] = None
                    self.submit = None
                    self.urb = None
                    return
            self.rel_pkt += 1
            
            #if args.verbose:
            #    print("Header size: %lu" % (usb_urb_sz,))
            #    print_urb(urb)
    
            if urb_error(self.urb):
                self.erros + 1
                if args.halt:
                    print("oh noes!")
                    sys.exit(1)
            
            if is_urb_complete(self.urb):
                if args.verbose:
                    print('Pending (%d):' % (len(g_pending),))
                    for k in g_pending:
                        print('  %s' % (urb_id_str(k),))
                # for some reason usbmon will occasionally give packets out of order
                if not self.urb.id in g_pending:
                    #raise Exception("Packet %s missing submit.  URB ID: 0x%016lX" % (self.pktn_str(), self.urb.id))
                    comment("WARNING: Packet %s missing submit.  URB ID: 0x%016lX" % (self.pktn_str(), self.urb.id))
                    self.pending_complete[self.urb.id] = (self.urb, dat_cur)
                else:
                    self.process_complete(dat_cur)
    
            elif is_urb_submit(self.urb):
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
                    g_pending[self.urb.id] = pending
                    printv('Added pending bulk URB %s' % self.urb.id)
                    
            self.submit = None
            self.urb = None
        except:
            print('ERROR: packet %s' % self.pktn_str())
            raise

    def pktn_str(self):
        if args.rel_pkt:
            return self.rel_pkt
        else:
            return self.g_cur_packet

    def process_complete(self, dat_cur):
        printv("process_complete")
        self.submit = g_pending[self.urb.id]
        # Done with it, get rid of it
        del g_pending[self.urb.id]

        # Discarded?
        if self.submit is None:
            return

        self.packnum()

        if self.previous_urb_complete_kept is not None:
            '''
            For bulk packets this can get tricky
            The intention was mostly for control packets where timing might be more critical
            '''
        
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
    
        printv('Remaining data: %d' % (len(dat_cur)))
        #printv('ctrlrequest: %d' % (len(self.urb.ctrlrequest)))
        # Skip xfer_stage
        dat_cur = dat_cur[1:]
        ctrl = usb_ctrlrequest(dat_cur[0:usb_ctrlrequest_sz])
        dat_cur = dat_cur[usb_ctrlrequest_sz:]
        
        if args.verbose:
            print("Packet %s control submit (control info size %lu)" % (self.pktn_str(), 666))
            print("    bRequestType: %s (0x%02X)" % (request_type2str(ctrl.bRequestType), ctrl.bRequestType))
            #print("    bRequest: %s (0x%02X)" % (request2str(ctrl), ctrl.bRequest))
            print("    wValue: 0x%04X" % (ctrl.wValue))
            print("    wIndex: 0x%04X" % (ctrl.wIndex))
            print("    wLength: 0x%04X" % (ctrl.wLength))
        
        if (ctrl.bRequestType & URB_TRANSFER_IN) == URB_TRANSFER_IN:
            dbg("%d: IN" % (self.g_cur_packet))
        else:
            dbg("%d: OUT" % (self.g_cur_packet))
            pending.m_data_out = str(dat_cur)
        
        pending.m_ctrl = ctrl
        pending.packet_number = self.pktn_str()
        g_pending[self.urb.id] = pending
        printv('Added pending control URB %s, len %d' % (urb_id_str(self.urb.id), len(g_pending)))


    def processControlCompleteIn(self, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = self.submit.m_ctrl.wLength

        # Skip xfer_stage
        dat_cur = dat_cur[1:]
        #print 'shorten'

        # Is it legal to have a 0 length control in?
        if self.submit.m_ctrl.wLength:
            data_str = "buff"
            data_size = self.submit.m_ctrl.wLength

        # Verify we actually have enough / expected
        # If exact match don't care
        if len(dat_cur) != max_payload_sz:
            if len(dat_cur) < max_payload_sz:
                comment("NOTE:: req max %u but got %u" % (max_payload_sz, len(dat_cur)))
            else:
                raise Exception('invalid response')
        
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

            
    def processControlCompleteOut(self, dat_cur):
        data_size = 0
        data_str = "None"
        data = None
    
        #print 'Control out w/ len %d' % len(submit.m_data_out)

        # print "Data out size: %u vs urb size %u" % (submit.m_data_out_size, submit.m_urb.data_length )
        # For some reason the request data is in the reply
        # Skip xfer_type
        data = dat_cur[1:]

        if data:
            data_str = bytes2AnonArray(data)
            data_size = len(data)            

        oj['data'].append({
                'type': 'controlWrite',
                'reqt': self.submit.m_ctrl.bRequestType, 
                'req': self.submit.m_ctrl.bRequest,
                'val': self.submit.m_ctrl.wValue, 
                'ind': self.submit.m_ctrl.wIndex, 
                'data': bytes2AnonArray(data),
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
    
        printv('Remaining data: %d' % (len(dat_cur)))

        # printv("Packet %d bulk submit (control info size %lu)" % (self.pktn_str(), 666))

        
        if self.urb.endpoint & URB_TRANSFER_IN:
            dbg("%d: IN" % (self.g_cur_packet))
        else:
            dbg("%d: OUT" % (self.g_cur_packet))
            if len(dat_cur) != self.urb.data_length:
                comment("WARNING: remaining bytes %d != expected payload out bytes %d" % (len(dat_cur), self.urb.data_length))
                hexdump(dat_cur, "  ")
                raise Exception('See above')
            pending.m_data_out = str(dat_cur)

        
        pending.packet_number = self.pktn_str()
        g_pending[self.urb.id] = pending
        printV('Added pending bulk URB %s' % self.urb.id)


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
        
        
        
        # output below
        oj['data'].append({
                'type': 'bulkRead',
                'endp': self.submit.m_urb.endpoint, 
                'len': data_size,
                'data': bytes2AnonArray(dat_cur),
                'packn': self.packnumt(),
                })
        
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
            
    
        
    
    
    def processBulkCompleteOut(self, dat_cur):
        data_size = 0
        
        oj['data'].append({
                'type': 'bulkWrite',
                'endp': self.submit.m_urb.endpoint, 
                'data': bytes2AnonArray(self.submit.m_data_out),
                'packn': self.packnumt(),
                })

    def processBulkComplete(self, dat_cur):
        if self.urb.endpoint & USB_DIR_IN:
            g_payload_bytes.bulk.in_ += self.urb.data_length
            self.processBulkCompleteIn(dat_cur)
        else:
            g_payload_bytes.bulk.out += self.urb.data_length
            self.processBulkCompleteOut(dat_cur)

    def processInterruptComplete(self, dat_cur):
        #print '%s# WARNING: omitting interrupt' % (indent,)
        pass

    
    def run(self):
        global oj

        oj = {
            'data': [],
            'fn': args.fin,
            'args': sys.argv,
        }
            
        if args.device_hi:
            self.device_keep = -1
            p = pcap.pcapObject()
            p.open_offline(args.fin)
            p.loop(-1, self.loop_cb_devmax)
            comment('Selected device %u' % self.device_keep)

        comment("Generated by usbrply")
        # comment("Date: %s" % (UVDCurDateTime()))
        comment("cmd: %s" % (' '.join(sys.argv),))

        comment("")
    
        dbg("parsing from range %s to %s" % (g_min_packet, g_max_packet))
        

        p = pcap.pcapObject()
        p.open_offline(args.fin)
        p.loop(-1, self.loop_cb)
        
        if len(g_pending) != 0:
            comment("WARNING: %lu pending requests" % (len(g_pending)))

        # TODO: find a better way to stream this
        for v in oj['data']:
            yield v

