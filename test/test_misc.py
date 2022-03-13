#!/usr/bin/env python3

import usbrply.parsers
import usbrply.printers
import unittest
import os
from usbrply import printer
from usbrply import parsers
import warnings


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
        usbrply.printers.run("json",
                             usbrply.parsers.pcap2json("test/data/lin1.pcapng",
                                                       argsj=self.argsj),
                             argsj=self.argsj)

    def test_print_pyprinter_lin(self):
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json("test/data/lin1.pcapng",
                                                       argsj=self.argsj),
                             argsj=self.argsj)

    def test_print_pyprinter_win(self):
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json("test/data/win1.pcapng",
                                                       argsj=self.argsj),
                             argsj=self.argsj)

    """
    Windows
    """

    def test_parse_win_pcap(self):
        """Windows .pcap parse test"""
        parsers.jgen2j(
            usbrply.parsers.pcap2json("test/data/win1.pcapng",
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

    def test_win_bulk_out(self):
        """
        Verify bulk out parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_setup_bulk-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_control_in(self):
        """
        Verify control in parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_setup_control-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_win_control_out(self):
        """
        Verify control out parses on Windows
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/win_setup_control-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    """
    Linux
    """

    def test_parse_lin_pcap(self):
        """Linux .pcap parse test"""
        parsers.jgen2j(
            usbrply.parsers.pcap2json("test/data/lin1.pcapng",
                                      argsj=self.argsj))

    def test_lin_control_in(self):
        """
        Verify control in parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_setup_control-in.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_lin_control_out(self):
        """
        Verify control out parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_setup_control-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_lin_interrupt_out(self):
        """
        Verify interrupt out parses on Linux
        """
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_interrupt_out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)



if __name__ == "__main__":
    unittest.main()  # run all tests
