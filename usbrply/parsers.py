"""
Aggregates parser engines together
"""

from . import lin_pcap
from . import win_pcap
from . import pcap_util


def pcap2json_prepare(fn, argsj={}):
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
    return gen

def pcap2json(fn, argsj={}):
    gen = pcap2json_prepare(fn, argsj)
    # k,v generator
    return gen.run()


def jgen2j(jgen):
    """
    Convert generator into static JSON
    Converts generates to lists
    byetarray must already be converted to hex
    """

    j = {}
    for k, v in jgen:
        # Convert nested generator to list
        if k == "data":
            v = list(v)
        j[k] = v
    return j
