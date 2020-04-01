"""
Aggregates parser engines together
"""

from . import lin_pcap
from . import win_pcap
from . import pcap_util

import json
import sys


def pcap_gen(args):
    # TODO: add Windows engine back in

    parser = args.parser
    if parser is "auto":
        parser = pcap_util.guess_parser(args.fin)
        # print("Guess parser: %s" % parser)

    cls = {
        "lin-pcap": lin_pcap.Gen,
        "win-pcap": win_pcap.Gen,
    }[parser]
    gen = cls(args)

    for p in gen.run():
        yield p


def pcap2json(args):

    oj = {
        'data': list(pcap_gen(args)),
        'fn': args.fin,
        'args': sys.argv,
    }

    # print(json.dumps(oj, sort_keys=True, indent=4, separators=(',', ': ')))
    return oj
