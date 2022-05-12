#!/usr/bin/env python3

import usbrply.parsers
import usbrply.printers
from usbrply import printer
from usbrply import parsers
from usbrply import filters
from usbrply.serial.parsers import FT2232CParser
from usbrply.serial.printers import JSONSPrinter
from usbrply.serial.mpsse import MPSSEParser
from usbrply import util
import unittest
import os
import json
import subprocess
import shutil
import binascii


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
    usbrply.printers.run("libusb-c",
                         usbrply.parsers.pcap2json(fn, argsj=argsj),
                         argsj=argsj)
    return j


class TestCommon(unittest.TestCase):
    def setUp(self):
        """Call before every test case."""
        print("")
        print("")
        print("")
        print("Start " + self._testMethodName)
        self.verbose = os.getenv("VERBOSE", "N") == "Y"
        printer.print_file = open("/dev/null", "w")
        self.argsj = {"verbose": self.verbose}
        self.tmp_dir = "/tmp/usbrply"
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)
        os.mkdir(self.tmp_dir)

    def tearDown(self):
        """Call after every test case."""
        if printer.print_file:
            printer.print_file.close()
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)


class TestCore(TestCommon):
    def print_all(self, fn):
        j = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=self.argsj))
        usbrply.printers.run("libusb-py",
                             usbrply.parsers.pcap2json(fn, argsj=self.argsj),
                             argsj=self.argsj)
        if 0:
            usbrply.printers.run("libusb-c",
                                 usbrply.parsers.pcap2json(fn,
                                                           argsj=self.argsj),
                                 argsj=self.argsj)
        return j

    """
    *************************************************************************
    misc tests
    *************************************************************************
    """

    def test_print_json(self):
        usbrply.printers.run(
            "json",
            usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    """
    *************************************************************************
    pyprinter tests
    *************************************************************************
    """

    def test_pyprinter_lin(self):
        usbrply.printers.run(
            "libusb-py",
            usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    def test_pyprinter_lin_wrapped(self):
        fn = "/tmp/usbrply/tmp.py"
        printer.print_file.close()
        with open(fn, "w") as printer.print_file:
            self.argsj["wrapper"] = True
            parsed = usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                               argsj=self.argsj)
            # filters.append("setup")
            # filters.append("commenter")
            filtered = filters.run(["vidpid"], parsed, self.argsj)
            usbrply.printers.run("libusb-py", filtered, argsj=self.argsj)

        subprocess.check_call("python3 %s -h >/dev/null" % fn, shell=True)

    def test_pyprinter_win(self):
        usbrply.printers.run(
            "libusb-py",
            usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    def test_pyprinter_win_wrapped(self):
        fn = "/tmp/usbrply/tmp.py"
        printer.print_file.close()

        with open(fn, "w") as printer.print_file:
            self.argsj["wrapper"] = True
            parsed = usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                               argsj=self.argsj)
            # filters.append("setup")
            # filters.append("commenter")
            filtered = filters.run(["vidpid"], parsed, self.argsj)
            usbrply.printers.run("libusb-py", filtered, argsj=self.argsj)

        subprocess.check_call("python3 %s -h >/dev/null" % fn, shell=True)

    """
    *************************************************************************
    cprinter tests
    *************************************************************************
    """

    # FIXME: very basic right now
    def test_cprinter_lin(self):
        usbrply.printers.run("libusb-c",
                             usbrply.parsers.pcap2json(
                                 "test/data/lin_control-out.pcapng",
                                 argsj=self.argsj),
                             argsj=self.argsj)

    def test_cprinter_lin_wrapped(self):
        fn = "/tmp/usbrply/tmp.c"
        printer.print_file.close()

        with open(fn, "w") as printer.print_file:
            self.argsj["wrapper"] = True
            parsed = usbrply.parsers.pcap2json("test/data/lin_misc.pcapng",
                                               argsj=self.argsj)
            # filters.append("setup")
            # filters.append("commenter")
            filtered = filters.run(["vidpid"], parsed, self.argsj)
            usbrply.printers.run("libusb-c", filtered, argsj=self.argsj)

        if os.getenv("USBRPLY_TEST_ALL") == "Y":
            subprocess.check_call(
                "gcc -I/usr/include/libusb-1.0 %s -lusb-1.0 -o %s.out >/dev/null"
                % (fn, fn),
                shell=True)

    def test_cprinter_win(self):
        usbrply.printers.run(
            "libusb-c",
            usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                      argsj=self.argsj),
            argsj=self.argsj)

    def test_cprinter_win_wrapped(self):
        fn = "/tmp/usbrply/tmp.c"
        printer.print_file.close()

        with open(fn, "w") as printer.print_file:
            self.argsj["wrapper"] = True
            parsed = usbrply.parsers.pcap2json("test/data/win_misc.pcapng",
                                               argsj=self.argsj)
            # filters.append("setup")
            # filters.append("commenter")
            filtered = filters.run(["vidpid"], parsed, self.argsj)
            usbrply.printers.run("libusb-c", filtered, argsj=self.argsj)

        if os.getenv("USBRPLY_TEST_ALL") == "Y":
            subprocess.check_call(
                "gcc -I/usr/include/libusb-1.0 %s -lusb-1.0 -o %s.out >/dev/null"
                % (fn, fn),
                shell=True)

    """
    *************************************************************************
    Windows packet tests
    *************************************************************************
    """

    def test_win_packets(self):
        """Windows large .pcap parse test"""
        self.print_all("test/data/win_misc.pcapng")

    def test_win_pipes(self):
        """
        Verify special PIPE setup packets are handled:
        -URB_FUNCTION_ABORT_PIPE
        -URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL

        Not exactly sure what this is but its at the beginning of my test capture
        Normally there?
        """
        self.print_all("test/data/win_setup_pipes.pcapng")
        self.print_all("test/data/win_abort-pipe.pcapng")
        self.print_all("test/data/win_pipe-stall.pcapng")

    def test_win_interrupts(self):
        assert len(
            find_packets(
                self.print_all("test/data/win_interrupts.pcapng"))) > 1

    def test_win_interrupt_in(self):
        find_packet(self.print_all("test/data/win_interrupt-in.pcapng"))

    def test_win_bulk_out(self):
        find_packet(self.print_all("test/data/win_bulk-out.pcapng"))

    def test_win_bulk_in(self):
        find_packet(self.print_all("test/data/win_bulk-in.pcapng"))

    def test_win_control_in(self):
        find_packet(self.print_all("test/data/win_control-in.pcapng"))

    def test_win_control_out(self):
        """
        Verify control out parses on Windows
        """
        packet = find_packet(
            self.print_all("test/data/win_control-out_len-0.pcapng"))
        assert len(packet["data"]) == 0

        packet = find_packet(
            self.print_all("test/data/win_control-out.pcapng"))
        assert packet["data"]

    def test_win_irp_status(self):
        """
        Code was failing irp's that had non-0 irp_status
        While success is typically 0, it's not strictly required
        """
        self.print_all("test/data/win_irp-status-120.pcapng")
        """
        FML
        https://github.com/JohnDMcMaster/usbrply/issues/70
        """
        self.print_all("test/data/win_irp-status-neg.pcapng")

    """
    *************************************************************************
    Linux packet tests
    *************************************************************************
    """

    def test_lin_packets(self):
        """Linux .pcap parse test"""
        self.print_all("test/data/lin_misc.pcapng")

    def test_parse_lin_setup(self):
        """Linux .pcap parse test"""
        self.print_all("test/data/lin_setup.pcapng")

    def test_lin_control_in(self):
        find_packet(self.print_all("test/data/lin_control-in.pcapng"))

    def test_lin_control_out(self):
        find_packet(self.print_all("test/data/lin_control-out.pcapng"))

    """
    def test_lin_interrupt_in(self):
        # FIXME: this file is bad, get new
        # find_packet(self.print_all("test/data/lin_interrupt-in.pcapng"))
    """

    def test_lin_interrupt_out(self):
        find_packet(self.print_all("test/data/lin_interrupt-out.pcapng"))


def data_serj2usbj(serj_data):
    """
    Convert USB serial JSON back to original USB JSON
    """
    ret = []
    for data in serj_data:
        if "raw_data" in data:
            ret += data["raw_data"]
        else:
            ret.append(data)
    return ret


def tx_string_data(serj):
    ret = ""
    for data in serj["data"]:
        if data["type"] == "write":
            ret += util.tostr(binascii.unhexlify(data["data"]))
    return ret


def tx_string_adata(serj):
    ret = ""
    for data in serj["data"]:
        if data["type"] == "write":
            ret += data["adata"]
    return ret


class TestSerial(TestCommon):
    def test_tx(self):
        fn = "test/data/ftdi_tx-l.pcapng"
        usbj = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=self.argsj))
        serj = FT2232CParser(argsj=self.argsj).run(usbj)
        assert "l" == tx_string_adata(serj)
        assert "l" == tx_string_data(serj)

    def test_tx_multi(self):
        fn = "test/ftdi/2022-04-26_01_ft232-goodfet_tx-hello.pcapng"
        usbj = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=self.argsj))
        serj = FT2232CParser(argsj=self.argsj).run(usbj)
        assert "hello" == tx_string_adata(serj)
        assert "hello" == tx_string_data(serj)

    def test_packet_loopback(self):
        """
        Convert pcap to serial format and then extract original pcap
        """
        fn = "test/ftdi/2022-04-26_01_ft232-goodfet_tx-hello.pcapng"
        self.argsj["keep_everything"] = True

        usbj = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=self.argsj))
        serj = FT2232CParser(argsj=self.argsj).run(usbj)
        data_back = data_serj2usbj(serj["data"])
        assert usbj["data"] == data_back

    def test_mpsee(self):
        fn = "test/ftdi/2022-04-26_01_ft232-goodfet_tx-hello.pcapng"
        usbj = parsers.jgen2j(usbrply.parsers.pcap2json(fn, argsj=self.argsj))
        serj = FT2232CParser(argsj=self.argsj).run(usbj)
        mpseej = MPSSEParser(argsj=self.argsj).run(serj)


if __name__ == "__main__":
    unittest.main()  # run all tests
