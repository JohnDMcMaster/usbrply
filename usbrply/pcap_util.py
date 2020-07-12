#!/usr/bin/env python

from .usb import *

# High performance C pcap librar
# Python 2 only, no longer maintained
try:
    import pcap
except ImportError:
    pcap = None

# Slow but reliable pure Python
try:
    import pcapng
except ImportError:
    pcapng = None

import sys
"""
Quick hack to detect packet format
I don't think the API i'm using 
"""


def guess_linux(buff):
    """
    linux heuristics
    0x8: one of SCE
    0x1C:0x1F (urb status): 0 => success, almost always
        windows: 
    """
    if len(buff) < 0x30:
        return False
    return sum(buff[0x1C:0x20]) == 0


def guess_windows(buff):
    """
    windows heuristics
    0xA:0xD (error code): 0 => success, almost always
        linux: endpoint, device, bus id. Unlikely to be 0
    0x10 (IRP information): either 0 or 1
    """
    if len(buff) < 0x24:
        return False
    return sum(buff[0x0A:0x0E]) == 0


class PcapParser(object):
    def __init__(self, fn, use_pcapng=None):
        self.fn = fn

        # Select library
        self.use_pcapng = use_pcapng
        if self.use_pcapng is None:
            # User higher performance library if available
            self.use_pcapng = False if pcap else True
        # self.pcapng = "pcapng" in argsj["parser"]
        if self.use_pcapng:
            assert pcapng, "pcapng library requested but no pcapng library"
        else:
            assert pcap, "pcap library requested but no pcap library"

        # Initialize library
        if self.use_pcapng:
            self.fp = open(fn, 'rb')
            self.scanner = pcapng.FileScanner(self.fp)
            self.scanner_iter = self.scanner.__iter__()
        else:
            self.pcap = pcap.pcapObject()
            self.pcap.open_offline(fn)

    def next(self, loop_cb):
        """return True if there was data and might be more, False if nothing was processed"""
        if self.use_pcapng:
            while True:
                try:
                    block = self.scanner_iter.next()
                except StopIteration:
                    return False

                if not isinstance(block, pcapng.blocks.EnhancedPacket):
                    continue
                loop_cb(block.captured_len, block.packet_data, block.timestamp)
                return True
        else:
            got = [False]

            # return code isn't given to indicate end
            def my_loop_cb(*args, **kwargs):
                got[0] = True
                loop_cb(*args, **kwargs)

            self.pcap.loop(1, my_loop_cb)
            return got[0]


def load_pcap(fn, loop_cb, lim=float('inf'), use_pcapng=None):
    parser = PcapParser(fn, use_pcapng=use_pcapng)
    i = 0
    while parser.next(loop_cb):
        i += 1
        if i >= lim:
            break


def guess_parser(fn):
    windows = [0]
    linux = [0]

    def loop_cb_guess(caplen, packet, ts):
        packet = bytearray(packet)
        if guess_linux(packet):
            linux[0] += 1
        if guess_windows(packet):
            windows[0] += 1

    load_pcap(fn, loop_cb_guess, lim=3)

    if windows[0]:
        assert linux[0] == 0
        return "win-pcap"
    if linux[0]:
        assert windows[0] == 0
        return "lin-pcap"
    assert 0, "failed to identify packet format"
