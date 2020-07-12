"""
Aggregates parser engines together
"""

from . import lin_pcap
from . import win_pcap
from . import pcap_util


def pcap2json(fn, argsj={}):
    """
    argsj: argument dict
    """

    # TODO: add Windows engine back in

    parser = argsj.get("parser", "auto")
    if parser == "auto":
        parser = pcap_util.guess_parser(fn)
        # print("Guess parser: %s" % parser)
        argsj["parser"] = parser

    cls = {
        "lin-pcap": lin_pcap.Gen,
        "lin-pcapng": lin_pcap.Gen,
        "win-pcap": win_pcap.Gen,
        "win-pcapng": win_pcap.Gen,
    }[parser]
    gen = cls(fn, argsj)

    # k,v generator
    return gen.run()


def jgen2j(jgen):
    # Convert generator into static JSON
    j = {}
    for k, v in jgen:
        if k == "data":
            v = list(v)
        j[k] = v
    return j
