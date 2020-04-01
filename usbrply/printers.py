from printer import JSONPrinter
from pyprinter import LibusbPyPrinter


def run(args, j):
    pass

    cls = {
        "json": JSONPrinter,
        # "libusb-c": LibusbCPrinter,
        "libusb-py": LibusbPyPrinter,
        # "linux": LinuxPrinter,
    }[args.ofmt]

    printer = cls(args)
    printer.run(j)
