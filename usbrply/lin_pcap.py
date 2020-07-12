#!/usr/bin/env python

from .usb import *
from .util import hexdump

import pcap
import sys
import binascii
import struct
from collections import namedtuple
import os
import errno

verbose = False

g_min_packet = 0
g_max_packet = float('inf')

jbuff = None


def dbg(s):
    if verbose:
        print(s)


def comment(s):
    dbg(("comment", s))
    jbuff.append({'type': 'comment', 'v': s})


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


def update_delta(pb):
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
usb_ctrlrequest_nt = namedtuple(
    'usb_ctrlrequest',
    (
        'bRequestType',
        'bRequest',
        'wValue',
        'wIndex',
        'wLength',
        # FIXME: what exactly are these?
        'res'))
usb_ctrlrequest_fmt = '<BBHHHH'
usb_ctrlrequest_sz = struct.calcsize(usb_ctrlrequest_fmt)


def usb_ctrlrequest(s):
    return usb_ctrlrequest_nt(*struct.unpack(usb_ctrlrequest_fmt, bytes(s)))


def bytes2AnonArray(bytes_data, byte_type="uint8_t"):
    # In Python2 bytes_data is a string, in Python3 it's bytes.
    # The element type is different (string vs int) and we have to deal
    # with that when printing this number as hex.
    if sys.version_info[0] == 2:
        myord = ord
    else:
        myord = lambda x: x
    return binascii.hexlify(bytes_data)


def deviceStr():
    # return "dev.udev"
    return "udev"


def print_urb(urb):
    print("URB id: 0x%016lX" % (urb.id))
    print("  type: %s (%c / 0x%02X)" %
          (urb_type2str[urb.type], urb.type, urb.type))
    #print("    dir: %s" % ('IN' if urb.type & URB_TRANSFER_IN else 'OUT',))
    print("  transfer_type: %s (0x%02X)" %
          (transfer2str[urb.transfer_type], urb.transfer_type))
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
usb_urb_nt = namedtuple(
    'usb_urb',
    (
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
        'ctrlrequest',
    ))
usb_urb_fmt = (
    '<'
    'Q'  # id
    'B'
    'B'
    'B'
    'B'  # device
    'H'
    'B'
    'B'
    'Q'  # sec
    'I'
    'i'
    'I'  # length
    'I'
    '24s')
usb_urb_sz = struct.calcsize(usb_urb_fmt)


def usb_urb(s):
    return usb_urb_nt(*struct.unpack(usb_urb_fmt, bytes(s)))


class Gen:
    def __init__(self, fn, argsj={}):
        global verbose

        verbose = argsj.get("verbose", False)
        self.verbose = verbose

        self.arg_fin = fn
        # XXX: don't think this is actually used, verify
        self.arg_fx2 = argsj.get("fx2", False)
        self.arg_device = argsj.get("device", None)
        self.arg_device_hi = argsj.get("device_hi", True)
        self.arg_setup = argsj.get("setup", False)
        self.arg_halt = argsj.get("halt", True)
        self.arg_remoteio = argsj.get("remoteio", False)
        self.arg_rel_pkt = argsj.get("rel_pkt", False)
        self.arg_print_short = argsj.get("print_short", False)
        self.arg_comment = argsj.get("comment", False)
        self.arg_packet_numbers = argsj.get("packet_numbers", True)

        self.cur_packn = 0
        self.rel_pkt = 0

        # Pending requests
        # Typically size 0-1 but sometimes more pile up
        # Entry can be set to None which means drop on complete
        # Holds PendingRXs
        self.pending_complete = {}
        # Got a complete wi/o a submit
        # These are less common but they happen somewhat regularly
        # Holds (self.urb, dat_cur)
        self.pending_submit = {}

    """
    @property
    def arg_setup(self):
        return bool(self.args.get("setup", True))
    """

    def run(self):
        global jbuff

        yield 'parser', "lin-pcap"
        yield "fn", self.arg_fin
        yield 'args', sys.argv
        yield 'packet_min', g_min_packet
        yield 'packet_max', g_max_packet

        jbuff = []
        comment('Source: Linux pcap (usbmon)')

        if self.arg_device_hi:
            self.arg_device = -1
            p = pcap.pcapObject()
            p.open_offline(self.arg_fin)
            p.loop(-1, self.loop_cb_devmax)
            comment('Selected device %u' % self.arg_device)
            self.cur_packn = 0

        dbg("parsing from range %s to %s" % (g_min_packet, g_max_packet))

        p = pcap.pcapObject()
        p.open_offline(self.arg_fin)
        p.loop(-1, self.loop_cb)

        if len(self.pending_complete) != 0:
            warning("%lu pending complete requests" %
                    (len(self.pending_complete)))
        if len(self.pending_submit) != 0:
            warning("%lu pending submit requests" % (len(self.pending_submit)))

        # TODO: find a better way to stream this
        yield "data", jbuff

    def loop_cb_devmax(self, caplen, packet, ts):
        self.cur_packn += 1
        if self.cur_packn < g_min_packet or self.cur_packn > g_max_packet:
            # print("# Skipping packet %d" % (self.cur_packn))
            return

        if caplen != len(packet):
            print("packet %s: malformed, caplen %d != len %d", self.pktn_str(),
                  caplen, len(packet))
            return
        if self.verbose:
            print('Len: %d' % len(packet))

        dbg("Length %u" % (len(packet), ))
        if len(packet) < usb_urb_sz:
            hexdump(packet)
            raise ValueError("Packet size %d is not min size %d" %
                             (len(packet), usb_urb_sz))

        # caplen is actual length, len is reported
        self.urb_raw = packet
        self.urb = usb_urb(packet[0:usb_urb_sz])
        dat_cur = packet[usb_urb_sz:]

        self.arg_device = max(self.arg_device, self.urb.device)

    def loop_cb(self, caplen, packet, ts):
        self.cur_packn += 1
        if self.cur_packn < g_min_packet or self.cur_packn > g_max_packet:
            # print("# Skipping packet %d" % (self.cur_packn))
            return
        if self.verbose:
            print("")
            print("")
            print("")
            print('PACKET %s' % (self.cur_packn, ))

        if caplen != len(packet):
            print("packet %s: malformed, caplen %d != len %d", self.pktn_str(),
                  caplen, len(packet))
            return
        if self.verbose:
            print('Len: %d' % len(packet))

        dbg("Length %u" % (len(packet), ))
        if len(packet) < usb_urb_sz:
            hexdump(packet)
            raise ValueError("Packet size %d is not min size %d" %
                             (len(packet), usb_urb_sz))

        # caplen is actual length, len is reported
        self.urb_raw = packet
        self.urb = usb_urb(packet[0:usb_urb_sz])
        dat_cur = packet[usb_urb_sz:]

        # Main packet filtering
        # Drop if not specified device
        if self.arg_device is not None and self.urb.device != self.arg_device:
            return
        # Drop if is generic device management traffic
        if not self.arg_setup and self.urb.transfer_type == URB_CONTROL:
            ctrl = usb_ctrlrequest(self.urb.ctrlrequest[0:usb_ctrlrequest_sz])
            reqst = req2s(ctrl, fx2=self.arg_fx2)
            if reqst in setup_reqs or reqst == "GET_STATUS" and self.urb.type == URB_SUBMIT:
                self.pending_complete[self.urb.id] = None
                self.submit = None
                self.urb = None
                return
        self.rel_pkt += 1

        if self.verbose:
            print("Header size: %lu" % (usb_urb_sz, ))
            print_urb(self.urb)

        if self.urb.type == URB_ERROR:
            print("oh noes!")
            if self.arg_halt:
                sys.exit(1)

        if self.urb.type == URB_COMPLETE:
            if self.verbose:
                print('Pending completes (%d):' %
                      (len(self.pending_complete), ))
                for k in self.pending_complete:
                    print('  %s' % (k, ))
            # for some reason usbmon will occasionally give packets out of order
            if not self.urb.id in self.pending_complete:
                #raise Exception("Packet %s missing submit.  URB ID: 0x%016lX" % (self.pktn_str(), self.urb.id))
                warning("Packet %s missing submit.  URB ID: 0x%016lX" %
                        (self.pktn_str(), self.urb.id))
                self.pending_submit[self.urb.id] = (self.urb, dat_cur)
            else:
                self.process_complete(self.pending_complete[self.urb.id],
                                      self.urb, dat_cur)

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
                if self.verbose:
                    print('Added pending interrupt URB 0x%016lX' % self.urb.id)
                self.pending_complete[self.urb.id] = pending

            # After processing check if it should trigger additional processing
            if self.urb.id in self.pending_submit:
                # oh snap solved a temporal anomaly
                comment(
                    "Packet %s: received 0x%016lX submit after complete (probably recycled URB)"
                    % (self.cur_packn, self.urb.id))
                # Add but will be immediately popped
                # is this resolution is actually a recycled URB and this would mix up the packet between transactions?
                if 0:
                    urb_complete, complete_dat_cur = self.pending_submit[
                        self.urb.id]
                    self.process_complete(self.pending_complete[self.urb.id],
                                          urb_complete, complete_dat_cur)

        self.submit = None
        self.urb = None

    def pktn_str(self):
        if self.arg_rel_pkt:
            return self.rel_pkt
        else:
            return self.cur_packn

    def process_complete(self, pending_rx, urb_complete, dat_cur):
        """
        Warning: this may be called with current urb as either the submit or the complete
        Normalize here which may swap self.urb
        """
        # assert type(pending_rx) is PendingRX, type(pending_rx)
        self.submit = pending_rx
        self.urb = urb_complete

        # Discarded?
        if self.submit is not None:
            self.packnum()

            # What was EREMOTEIO?
            EREMOTEIO = -121
            if self.urb.status != 0 and not (not self.arg_remoteio
                                             and self.urb.status == EREMOTEIO):
                warning('complete code %s (%s)' %
                        (self.urb.status,
                         errno.errorcode.get(-self.urb.status, "unknown")))

            # Find the matching submit request
            if self.urb.transfer_type == URB_CONTROL:
                self.processControlComplete(dat_cur)
            elif self.urb.transfer_type == URB_BULK:
                self.processBulkComplete(dat_cur)
            elif self.urb.transfer_type == URB_INTERRUPT:
                self.processInterruptComplete(dat_cur)

        if self.urb.id in self.pending_submit:
            del self.pending_submit[self.urb.id]
        if self.urb.id in self.pending_complete:
            del self.pending_complete[self.urb.id]

    def processControlSubmit(self, dat_cur):
        pending = PendingRX()
        pending.raw = self.urb_raw
        pending.m_urb = self.urb

        if self.verbose:
            print('Remaining data: %d' % (len(dat_cur)))
            print('ctrlrequest: %d' % (len(self.urb.ctrlrequest)))
        ctrl = usb_ctrlrequest(self.urb.ctrlrequest[0:usb_ctrlrequest_sz])

        if self.verbose:
            print("Packet %s control submit (control info size %lu)" %
                  (self.pktn_str(), 666))
            print("    bRequestType: %s (0x%02X)" %
                  (request_type2str(ctrl.bRequestType), ctrl.bRequestType))
            #print("    bRequest: %s (0x%02X)" % (request2str(ctrl), ctrl.bRequest))
            print("    wValue: 0x%04X" % (ctrl.wValue))
            print("    wIndex: 0x%04X" % (ctrl.wIndex))
            print("    wLength: 0x%04X" % (ctrl.wLength))

        if (ctrl.bRequestType & URB_TRANSFER_IN) == URB_TRANSFER_IN:
            dbg("%d: IN" % (self.cur_packn))
        else:
            dbg("%d: OUT" % (self.cur_packn))
            if len(dat_cur) != self.urb.data_length:
                warning("remaining bytes %d != expected payload out bytes %d" %
                        (len(dat_cur), self.urb.data_length))
                hexdump(dat_cur, "  ")
                #raise Exception('See above')
            pending.m_data_out = bytes(dat_cur)

        pending.m_ctrl = ctrl
        pending.packet_number = self.pktn_str()
        if self.verbose:
            print('Added pending control URB %s' % self.urb.id)
        self.pending_complete[self.urb.id] = pending

    def processControlCompleteIn(self, dat_cur):
        packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = self.submit.m_ctrl.wLength

        # Is it legal to have a 0 length control in?
        if self.submit.m_ctrl.wLength:
            data_str = "buff"
            data_size = self.submit.m_ctrl.wLength

        # Verify we actually have enough / expected
        # If exact match don't care
        if len(dat_cur) != max_payload_sz:
            if len(dat_cur) < max_payload_sz:
                if self.arg_print_short:
                    comment("NOTE:: req max %u but got %u" %
                            (max_payload_sz, len(dat_cur)))
            else:
                raise Exception('invalid response')

        jbuff.append({
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
            if self.arg_packet_numbers:
                packet_numbering = "packet %s/%s" % (self.submit.packet_number,
                                                     self.pktn_str())
            else:
                # TODO: consider counting instead of by captured index
                packet_numbering = "packet"

    def processControlCompleteOut(self, dat_cur):
        data_size = 0
        data_str = "None"

        #print('Control out w/ len %d' % len(submit.m_data_out))

        # print("Data out size: %u vs urb size %u" % (submit.m_data_out_size, submit.m_urb.data_length ))
        if len(self.submit.m_data_out):
            # Note that its the submit from earlier, not the ack that we care about
            data_str = bytes2AnonArray(self.submit.m_data_out)
            data_size = len(self.submit.m_data_out)

        jbuff.append({
            'type': 'controlWrite',
            'bRequestType': self.submit.m_ctrl.bRequestType,
            'bRequest': self.submit.m_ctrl.bRequest,
            'wValue': self.submit.m_ctrl.wValue,
            'wIndex': self.submit.m_ctrl.wIndex,
            'data': bytes2AnonArray(self.submit.m_data_out),
            'packn': self.packnumt(),
        })

    def processControlComplete(self, dat_cur):
        if self.arg_comment:
            req_comment(self.submit.m_ctrl, self.submit.m_data_out, comment)

        if self.submit.m_ctrl.bRequestType & URB_TRANSFER_IN:
            self.processControlCompleteIn(dat_cur)
        else:
            self.processControlCompleteOut(dat_cur)

    def print_stat(self):
        bulk = g_payload_bytes.bulk
        # payload_bytes_type_t *ctrl = &g_payload_bytes.ctrl

        print("Transer statistics")
        print("    Bulk")
        print("        In: %u (delta %u), req: %u (delta %u)" %
              (bulk.in_, bulk.in_ - bulk.in_last, bulk.req_in,
               bulk.req_in - bulk.req_in_last))
        update_delta(bulk)
        print("        Out: %u, req: %u" %
              (g_payload_bytes.bulk.out, g_payload_bytes.bulk.req_out))
        print("    Control")
        print("        In: %u, req: %u" %
              (g_payload_bytes.ctrl.in_, g_payload_bytes.ctrl.req_in))
        print("        Out: %u, req: %u" %
              (g_payload_bytes.ctrl.out, g_payload_bytes.ctrl.req_out))

    def packnum(self):
        '''
        Originally I didn't print anything but found that it was better to keep the line numbers the same
        so that I could diff and then easier back annotate with packet numbers
        '''
        if self.arg_packet_numbers:
            comment("Generated from packet %s/%s" %
                    (self.submit.packet_number, self.pktn_str()))
        else:
            #comment("Generated from packet %s/%s" % (None, None))
            pass

    def packnumt(self):
        if self.arg_packet_numbers:
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

        if self.verbose:
            print('Remaining data: %d' % (len(dat_cur)))

        #if self.verbose:
        #    print("Packet %d bulk submit (control info size %lu)" % (self.pktn_str(), 666))

        if self.urb.endpoint & URB_TRANSFER_IN:
            dbg("%d: IN" % (self.cur_packn))
        else:
            dbg("%d: OUT" % (self.cur_packn))
            if len(dat_cur) != self.urb.data_length:
                warning("remaining bytes %d != expected payload out bytes %d" %
                        (len(dat_cur), self.urb.data_length))
                hexdump(dat_cur, "  ")
                #raise Exception('See above')
            pending.m_data_out = bytes(dat_cur)

        pending.packet_number = self.pktn_str()
        self.pending_complete[self.urb.id] = pending
        if self.verbose:
            print('Added pending bulk URB 0x%016lX' % self.urb.id)

    def processBulkCompleteIn(self, dat_cur):
        # packet_numbering = ''
        data_size = 0
        data_str = "None"
        max_payload_sz = self.submit.m_urb.length

        # FIXME: this is a messy conversion artfact from the C code
        # Is it legal to have a 0 length bulk in?
        if max_payload_sz:
            data_str = "buff"
            data_size = max_payload_sz

        # output below
        jbuff.append({
            'type': 'bulkRead',
            'endp': self.submit.m_urb.endpoint,
            'len': data_size,
            'data': bytes2AnonArray(dat_cur),
            'packn': self.packnumt(),
            'packm': self.submit.packet_number,
        })

        # Verify we actually have enough / expected
        # If exact match don't care
        if len(dat_cur) > max_payload_sz:
            warning('requested max %u bytes but got %u' %
                    (max_payload_sz, len(dat_cur)))
        elif len(dat_cur) < max_payload_sz and self.arg_print_short:
            comment("NOTE:: req max %u but got %u" %
                    (max_payload_sz, len(dat_cur)))
        """
        if max_payload_sz:
            if args.packet_numbers:
                packet_numbering = "packet %s/%s" % (self.submit.packet_number,
                                                     self.pktn_str())
            else:
                # TODO: consider counting instead of by captured index
                packet_numbering = "packet"
        """

    def processBulkCompleteOut(self, dat_cur):
        # output below
        jbuff.append({
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
        warning('omitting interrupt')
