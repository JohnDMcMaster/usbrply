from __future__ import print_function
import json
import sys
from . import parsers

indent = ""

print_file = sys.stdout


def default_print_file(fname, cap_file):
    global print_file
    """
    Given argument for explicit file name and a cap file,
    default to the file name, otherwise munge cap file into .py version
    """
    if not fname:
        fname = cap_file.replace('.pcapng',
                                 '.py').replace('.pcap',
                                                '.py').replace('.cap', '.py')

    assert fname != cap_file, (fname, cap_file)
    print_file = open(fname, "w")


def indent_inc():
    global indent

    indent += "    "


def indent_dec():
    global indent

    indent = indent[4:]


def indented(s):
    print("%s%s" % (indent, s), file=print_file)


def get_indent():
    return indent


class Printer(object):
    def __init__(self, argsj):
        self.argsj = argsj

    def run(self, j):
        raise Exception("Required")


class JSONPrinter(Printer):
    def __init__(self, argsj):
        Printer.__init__(self, argsj)

    def run(self, jgen):
        j = parsers.jgen2j(jgen)

        json.dump(j,
                  print_file,
                  sort_keys=True,
                  indent=4,
                  separators=(',', ': '))
