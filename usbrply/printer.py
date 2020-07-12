from __future__ import print_function
import json
import sys

indent = ""

print_file = sys.stdout

def indent_inc():
    global indent

    indent += "    "


def indent_dec():
    global indent

    indent = indent[4:]


def indented(s):
    print("%s%s" % (indent, s), file=print_file)


class Printer(object):
    def __init__(self, argsj):
        self.argsj = argsj

    def run(self, j):
        raise Exception("Required")


class JSONPrinter(Printer):
    def __init__(self, argsj):
        Printer.__init__(self, argsj)

    def run(self, j):
        json.dump(j, print_file, sort_keys=True, indent=4, separators=(',', ': '))
