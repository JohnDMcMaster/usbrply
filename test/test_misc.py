#!/usr/bin/env python

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

    def tearDown(self):
        """Call after every test case."""
        printer.print_file.close()

    def test_parse_win_pcap(self):
        """Windows .pcap parse test"""
        parsers.jgen2j(usbrply.parsers.pcap2json("test/data/win1.pcapng"))

    def test_parse_lin_pcap(self):
        """Linux .pcap parse test"""
        parsers.jgen2j(usbrply.parsers.pcap2json("test/data/lin1.pcapng"))

    def test1(self):
        return
        j = parsers.jgen2j(usbrply.parsers.pcap2json("test/data/win1.pcapng"))
        for d in j["data"]:
            if d["type"] == "controlRead":
                print(d)

    def test_print_json(self):
        usbrply.printers.run(
            "json", usbrply.parsers.pcap2json("test/data/lin1.pcapng"))

    def test_print_pyprinter_lin(self):
        usbrply.printers.run(
            "libusb-py", usbrply.parsers.pcap2json("test/data/lin1.pcapng"))

    def test_print_pyprinter_win(self):
        usbrply.printers.run(
            "libusb-py", usbrply.parsers.pcap2json("test/data/win1.pcapng"))

    def test_win_interrupt(self):
        usbrply.printers.run(
            "json",
            usbrply.parsers.pcap2json("test/data/win_interrupt.pcapng"))


if __name__ == "__main__":
    unittest.main()  # run all tests
