import json

indent = ""


def indent_inc():
    global indent

    indent += "    "


def indent_dec():
    global indent

    indent = indent[4:]


def indented(s):
    print("%s%s" % (indent, s))


class Printer(object):
    def __init__(self, args):
        self.args = args

    def run(self, j):
        raise Exception("Required")


class JSONPrinter(Printer):
    def __init__(self, args):
        Printer.__init__(self, args)

    def run(self, j):
        print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))
