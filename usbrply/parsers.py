"""
Aggregates parser engines together
"""

from . import lin_pcap
from . import win_pcap
from . import pcap_util

import json
import sys


def pcap_gen(fn, argsj):
    """
    argsj: argument dict
    required keys:
    -fin
    """

    # TODO: add Windows engine back in

    parser = argsj.get("parser", "auto")
    if parser == "auto":
        parser = pcap_util.guess_parser(fn)
        # print("Guess parser: %s" % parser)

    cls = {
        "lin-pcap": lin_pcap.Gen,
        "win-pcap": win_pcap.Gen,
    }[parser]
    gen = cls(fn, argsj)

    for p in gen.run():
        yield p


def pcap2json(fn, argsj):

    oj = {
        'data': list(pcap_gen(fn, argsj)),
        'fn': fn,
        'args': argsj.get("argv", None),
    }

    # print(json.dumps(oj, sort_keys=True, indent=4, separators=(',', ': ')))
    return oj
