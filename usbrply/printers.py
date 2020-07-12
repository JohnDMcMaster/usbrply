from printer import JSONPrinter
from pyprinter import LibusbPyPrinter


def run(ofmt, argsj, j):
    pass

    cls = {
        "json": JSONPrinter,
        # "libusb-c": LibusbCPrinter,
        "libusb-py": LibusbPyPrinter,
        # "linux": LinuxPrinter,
    }[ofmt]

    printer = cls(argsj)
    printer.run(j)
