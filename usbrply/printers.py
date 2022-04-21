from .printer import JSONPrinter
from .pyprinter import LibusbPyPrinter
from .cprinter import LibusbCPrinter


def run(ofmt, j, argsj={}):
    cls = {
        "json": JSONPrinter,
        "libusb-c": LibusbCPrinter,
        "libusb-py": LibusbPyPrinter,
        # "linux": LinuxPrinter,
    }[ofmt]

    printer = cls(argsj)
    printer.run(j)
