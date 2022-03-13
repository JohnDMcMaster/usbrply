#!/usr/bin/env python3

import usbrply.parsers
import usbrply.printers
import unittest
import os
from usbrply import printer
from usbrply import parsers
import json


def printj(j):
    """For debugging"""
    print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))


def find_packets(j):
    """Return non-comment packets in json"""
    ret = []
    for packet in j["data"]:
        if packet["type"] == "comment":
            continue
        ret.append(packet)
    return ret


def find_packet(j):
    """Return the single packet in json"""
    packets = find_packets(j)
    assert len(packets) == 1, len(packets)
    return packets[0]


def run_printers_json(fn, argsj):
    j = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=argsj))
    usbrply.printers.run("libusb-py",
                         usbrply.parsers.pcap2json(fn, argsj=argsj),
                         argsj=argsj)
    return j


class TestCase(unittest.TestCase):
    def setUp(self):
        """Call before every test case."""
        print("")
        print("")
        print("")
        print("Start " + self._testMethodName)
        self.verbose = os.getenv("VERBOSE", "N") == "Y"
        #warnings.simplefilter("ignore")
        printer.print_file = open("/dev/null", "w")
        self.argsj = {"verbose": self.verbose}

    def tearDown(self):
        """Call after every test case."""
        printer.print_file.close()

    def test_print_json(self):
        usbrply.printers.run(
            "json",
            usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    def test_print_pyprinter_lin(self):
        usbrply.printers.run(
            "libusb-py",
            usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    def test_print_pyprinter_win(self):
        usbrply.printers.run(
            "libusb-py",
            usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    """
    Windows
    """

    def test_parse_win_pcap(self):
        """Windows .pcap parse test"""
        parsers.jgen2j(
            usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                      argsj=self.argsj))

    def test_win_pipes(self):
        """
        Verify special PIPE setup packets are handled:
        -URB_FUNCTION_ABORT_PIPE
        -URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL

        Not exactly sure what this is but its at the beginning of my test capture
        Normally there?
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_setup_pipes.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_interrupt(self):
        usbrply.printers.run("json",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_interrupt.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_interrupt_in(self):
        usbrply.printers.run("json",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_interrupt-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_bulk_out(self):
        """
        Verify bulk out parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_bulk-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_bulk_in(self):
        """
        Verify bulk in parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_bulk-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_control_in(self):
        """
        Verify control in parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_control-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_control_out(self):
        """
        Verify control out parses on Windows
        """
        packet = find_packet(
            run_printers_json("test/data/win_control-out_len-0.pcapng",
                              self.argsj))
        assert len(packet["data"]) == 0

        packet = find_packet(
            run_printers_json("test/data/win_control-out.pcapng", self.argsj))
        assert packet["data"]

    """
    Linux
    """

    def test_parse_lin_pcap(self):
        """Linux .pcap parse test"""
        parsers.jgen2j(
            usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                      argsj=self.argsj))

    def test_parse_lin_setup(self):
        """Linux .pcap parse test"""
        parsers.jgen2j(
            usbrply.parsers.pcap2json("test/data/lin_setup.pcapng",
                                      argsj=self.argsj))

    def test_lin_control_in(self):
        """
        Verify control in parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_control-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_lin_control_out(self):
        """
        Verify control out parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_control-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_lin_interrupt_in(self):
        """
        Verify interrupt in parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_interrupt-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_lin_interrupt_out(self):
        """
        Verify interrupt out parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_interrupt-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)


if __name__ == "__main__":
    unittest.main()  # run all tests
