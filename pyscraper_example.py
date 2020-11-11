import json
import subprocess

from usbrply.pyprinter import LibusbPyPrinter
from usbrply.printer import indented


class Scraper:
    def __init__(self, verbose=False):
        self.pyprint = LibusbPyPrinter(argsj={"wrapper": True},
                                       verbose=verbose)

    def parse_data(self, d):
        # Translate to higher level function
        if d["type"] == "controlRead" and d["bRequest"] == 0x02:
            indented("vendor_request1()")
        # Ignore bulk reads
        elif d["type"] == "bulkRead":
            pass
        # Default: print as normal python replay
        else:
            self.pyprint.parse_data(d)

    def run(self, j):
        self.pyprint.header()

        # Last wire command (ie non-comment)
        # Used to optionally generate timing
        self.prevd = None

        for d in j["data"]:
            self.parse_data(d)

        self.pyprint.footer()


def load_json(fin, usbrply=""):
    if fin.find('.cap') >= 0 or fin.find('.pcapng') >= 0:
        json_fn = '/tmp/scrape.json'
        cmd = 'usbrply %s --json %s >%s' % (usbrply, fin, json_fn)
        subprocess.check_call(cmd, shell=True)
    else:
        json_fn = fin

    j = json.load(open(json_fn))
    return j, json_fn


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--usbrply', default='')
    parser.add_argument('fin')
    args = parser.parse_args()

    j, json_fn = load_json(
        args.fin,
        args.usbrply,
    )

    scraper = Scraper()
    scraper.run(j)
