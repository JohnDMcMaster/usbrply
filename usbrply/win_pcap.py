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

from .usb import *

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

# Windows transfer stages
# Usb function: URB_FUNCTION_VENDOR_DEVICE (0x17)
XFER_SETUP = 0
# Usb function: URB_FUNCTION_CONTROL_TRANSFER (0x08)
XFER_DATA = 1
# Usb function: URB_FUNCTION_CONTROL_TRANSFER (0x08)
XFER_STATUS = 2

USBD_STATUS_SUCCESS = 0

# https://msdn.microsoft.com/en-us/library/windows/hardware/ff540409(v=vs.85).aspx
# https://github.com/wine-mirror/wine/blob/master/include/ddk/usb.h
URB_FUNCTION_CONTROL_TRANSFER = 0x08
URB_FUNCTION_VENDOR_DEVICE = 0x17

func_i2s = {
        0x0000: "SELECT_CONFIGURATION",
        0x0001: "SELECT_INTERFACE",
        0x0002: "ABORT_PIPE",
        0x0003: "TAKE_FRAME_LENGTH_CONTROL",
        0x0004: "RELEASE_FRAME_LENGTH_CONTROL",
        0x0005: "GET_FRAME_LENGTH",
        0x0006: "SET_FRAME_LENGTH",
        0x0007: "GET_CURRENT_FRAME_NUMBER",
        0x0008: "CONTROL_TRANSFER",
        0x0009: "BULK_OR_INTERRUPT_TRANSFER",
        0x000A: "ISOCH_TRANSFER",
        0x000B: "GET_DESCRIPTOR_FROM_DEVICE",
        0x000C: "SET_DESCRIPTOR_TO_DEVICE",
        0x000D: "SET_FEATURE_TO_DEVICE",
        0x000E: "SET_FEATURE_TO_INTERFACE",
        0x000F: "SET_FEATURE_TO_ENDPOINT",
        0x0010: "CLEAR_FEATURE_TO_DEVICE",
        0x0011: "CLEAR_FEATURE_TO_INTERFACE",
        0x0012: "CLEAR_FEATURE_TO_ENDPOINT",
        0x0013: "GET_STATUS_FROM_DEVICE",
        0x0014: "GET_STATUS_FROM_INTERFACE",
        0x0015: "GET_STATUS_FROM_ENDPOINT",
        0x0016: "RESERVED_0X0016",
        0x0017: "VENDOR_DEVICE",
        0x0018: "VENDOR_INTERFACE",
        0x0019: "VENDOR_ENDPOINT",
        0x001A: "CLASS_DEVICE",
        0x001B: "CLASS_INTERFACE",
        0x001C: "CLASS_ENDPOINT",
        0x001D: "RESERVE_0X001D",
        0x001E: "SYNC_RESET_PIPE_AND_CLEAR_STALL",
        0x001F: "CLASS_OTHER",
        0x0020: "VENDOR_OTHER",
        0x0021: "GET_STATUS_FROM_OTHER",
        0x0022: "CLEAR_FEATURE_TO_OTHER",
        0x0023: "SET_FEATURE_TO_OTHER",
        0x0024: "GET_DESCRIPTOR_FROM_ENDPOINT",
        0x0025: "SET_DESCRIPTOR_TO_ENDPOINT",
        0x0026: "GET_CONFIGURATION",
        0x0027: "GET_INTERFACE",
        0x0028: "GET_DESCRIPTOR_FROM_INTERFACE",
        0x0029: "SET_DESCRIPTOR_TO_INTERFACE",
        0x002A: "GET_MS_FEATURE_DESCRIPTOR",
        0x002B: "RESERVE_0X002B",
        0x002C: "RESERVE_0X002C",
        0x002D: "RESERVE_0X002D",
        0x002E: "RESERVE_0X002E",
        0x002F: "RESERVE_0X002F",
        0x0030: "SYNC_RESET_PIPE",
        0x0031: "SYNC_CLEAR_STALL",
        }

def func_str(func):
    return func_i2s.get(func, "0x%04X" % func)


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

# https://stackoverflow.com/questions/19110075/what-is-the-difference-between-pdo-and-fdo-in-windows-device-drivers
# PDO = Physical Device Object
# FDO = Functional Device Object
# Submit
INFO_FDO2PDO = 0
# Complete
INFO_PDO2FDO = 1

def irp_info_str(irp_info):
    if irp_info & 1:
        return "PDO2FDO (0x%02X)" % irp_info
    else:
        return "FDO2PDO (0x%02X)" % irp_info

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

'''
IRP: I/O request packet
https://msdn.microsoft.com/en-us/library/windows/hardware/ff550694(v=vs.85).aspx

also useful info
https://www.wireshark.org/docs/dfref/u/usb.html
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


def print_urb(urb):
    # unique per transaction, not packet
    print("URB id: %s" % (urb_id_str(urb.id)))
    print(" pcap_hdr_len: %s" % (urb.pcap_hdr_len,))
    print(" irp_status: %s" % (urb.irp_status,))
    print(" usb_func: %s" % (func_str(urb.usb_func),))
    print(" irp_info: %s" % (irp_info_str(urb.irp_info),))
    print(" bus_id: %s" % (urb.bus_id,))
    print(" device: %s" % (urb.device,))
    print(" endpoint: 0x%02X" % (urb.endpoint,))
    print(" transfer_type: %s" % (urb.transfer_type,))
    print(" data_length: %s" % (urb.data_length,))

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
            #if self.g_cur_packet >= 871:
            #    args.verbose = True

            if self.g_cur_packet < g_min_packet or self.g_cur_packet > g_max_packet:
                # print("# Skipping packet %d" % (self.g_cur_packet))
                return
            if args.verbose:
                print("")
                print("")
                print("")
                print('PACKET %s' % (self.g_cur_packet,))

            if caplen != len(packet):
                print("packet %s: malformed, caplen %d != len %d", self.pktn_str(), caplen, len(packet))
                return
            if args.verbose:
                # print('Len: %d' % len(packet))
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
    
            printv('ID %s, %s post-urb bytes' % (urb_id_str(self.urb.id), len(dat_cur)))
    
            # Main packet filtering
            # Drop if not specified device
            #print(self.pktn_str(), self.urb.device, args.device)
            if args.device is not None and self.urb.device != args.device:
                return
    
            # FIXME: hack to only process control for now
            if 0 and self.urb.transfer_type != URB_CONTROL:
                warning('packet %s: drop packet type %s' % (self.pktn_str(), transfer2str_safe(self.urb.transfer_type)))
                return
    
            # FIXME: hack to only process control for now
            if self.urb.transfer_type == URB_INTERRUPT:
                # warning('packet %s: drop packet type %s' % (self.pktn_str(), transfer2str_safe(self.urb.transfer_type)))
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
                    # Was the submit marked for ignore?
                    # For some reason these don't have status packets
                    if self.urb.id in g_pending and g_pending[self.urb.id] is None:
                        return True
                    # Keep any other pending packets
                    if self.urb.id in g_pending:
                        return False
                    # If not already submitted, must be a submit then
                    # but we could have started a capture before submit
                    if self.urb.irp_info & 1 == INFO_PDO2FDO and self.urb.transfer_type == URB_CONTROL:
                        # Skip xfer_stage
                        buf = dat_cur[1:usb_ctrlrequest_sz+1]
                        ctrl = usb_ctrlrequest(buf)
                        reqst = req2s(ctrl, fx2=args.fx2)
                        return (reqst in setup_reqs) or (reqst == "GET_STATUS" and (self.urb.endpoint & URB_TRANSFER_IN) == URB_TRANSFER_IN)

                if skip():
                    print('Drop setup packet %s' % self.pktn_str())
                    g_pending[self.urb.id] = None
                    self.submit = None
                    self.urb = None
                    return
            self.rel_pkt += 1
            
            if args.verbose:
                # print("Header size: %lu" % (usb_urb_sz,))
                print_urb(self.urb)
    
            if urb_error(self.urb):
                self.errors + 1
                if args.halt:
                    print("oh noes!")
                    sys.exit(1)
            
            # Complete?
            if self.urb.irp_info & 1 == INFO_PDO2FDO:
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
            # Oterhwise submit
            else:
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
        printv("Matched submit packet %s" % self.submit.packet_number)

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
                'bRequestType': self.submit.m_ctrl.bRequestType, 
                'bRequest': self.submit.m_ctrl.bRequest,
                'wValue': self.submit.m_ctrl.wValue, 
                'wIndex': self.submit.m_ctrl.wIndex, 
                'wLength': self.submit.m_ctrl.wLength,
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
                'bRequestType': self.submit.m_ctrl.bRequestType, 
                'bRequest': self.submit.m_ctrl.bRequest,
                'wValue': self.submit.m_ctrl.wValue, 
                'wIndex': self.submit.m_ctrl.wIndex, 
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
        
        print("Transer statistics")
        print("    Bulk")
        print("        In: %u (delta %u), req: %u (delta %u)" % (
                bulk.in_, bulk.in_ - bulk.in_last,
                bulk.req_in, bulk.req_in - bulk.req_in_last
                ))
        update_delta( bulk )
        print("        Out: %u, req: %u" % (g_payload_bytes.bulk.out, g_payload_bytes.bulk.req_out))
        print("    Control")
        print("        In: %u, req: %u" % (g_payload_bytes.ctrl.in_, g_payload_bytes.ctrl.req_in))
        print("        Out: %u, req: %u" % (g_payload_bytes.ctrl.out, g_payload_bytes.ctrl.req_out))

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
        if self.urb.endpoint & URB_TRANSFER_IN:
            g_payload_bytes.bulk.req_in += self.urb.data_length
        else:
            g_payload_bytes.bulk.req_out += self.urb.data_length

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
        printv('Added pending bulk URB %s' % self.urb.id)


    def processBulkCompleteIn(self, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"

        # looks like maybe windows doesn't report the request size?
        # think this is always 0
        assert self.submit.m_urb.data_length == 0
        
        # instead, use the recieved buffer size as a best estimated
        max_payload_sz = len(dat_cur)
        
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
        if self.urb.endpoint & URB_TRANSFER_IN:
            g_payload_bytes.bulk.in_ += self.urb.data_length
            self.processBulkCompleteIn(dat_cur)
        else:
            g_payload_bytes.bulk.out += self.urb.data_length
            self.processBulkCompleteOut(dat_cur)

    def processInterruptComplete(self, dat_cur):
        #warning("omitting interrupt")
        pass

    
    def loop_cb_devmax(self, caplen, packet, ts):
        self.g_cur_packet += 1
        if self.g_cur_packet < g_min_packet or self.g_cur_packet > g_max_packet:
            # print("# Skipping packet %d" % (self.g_cur_packet))
            return
        
        if caplen != len(packet):
            print("packet %s: malformed, caplen %d != len %d", self.pktn_str(), caplen, len(packet))
            return
        #if args.verbose:
        #    print('Len: %d' % len(packet))
        
        # dbg("Length %u" % (len(packet),))
        if len(packet) < usb_urb_sz:
            hexdump(packet)
            raise ValueError("Packet size %d is not min size %d" % (len(packet), usb_urb_sz))
    
        # caplen is actual length, len is reported
        self.urb_raw = packet
        self.urb = usb_urb(packet[0:usb_urb_sz])
        dat_cur = packet[usb_urb_sz:]

        self.device_keep = max(self.device_keep, self.urb.device)

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
            self.g_cur_packet = 0

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

