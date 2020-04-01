#!/usr/bin/env python

from .usb import *

import pcap
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

def guess_parser(fn):
    windows = [0]
    linux = [0]

    def loop_cb_guess(caplen, packet, ts):
        packet = bytearray(packet)
        if guess_linux(packet):
            linux[0] += 1
        if guess_windows(packet):
            windows[0] += 1

    p = pcap.pcapObject()
    p.open_offline(fn)
    p.loop(3, loop_cb_guess)
    
    if windows[0]:
        assert linux[0] == 0
        return "win-pcap"
    if linux[0]:
        assert windows[0] == 0
        return "lin-pcap"
    assert 0, "failed to identify packet format"
