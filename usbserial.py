#!/usr/bin/env python3

from usbrply.printer import Printer, indented, indent_inc, indent_dec
from usbrply.util import add_bool_arg
import usbrply.parsers
import usbrply.serial.parsers as sparsers
import usbrply.serial.printers as sprinters
from usbrply.serial import mpsse
import usbrply.main
from usbrply import parsers

import argparse


def main():
    parser = argparse.ArgumentParser(
        description='Decode USB-serial data (experimental / alpha quality)')
    parser.add_argument('--range', '-r', help='inclusive range like 123:456')
    """
    parser.add_argument('-k',
                        dest='ofmt',
                        default='libusb-py',
                        action='store_const',
                        const='linux',
                        help='output linux kernel')
    """
    parser.add_argument('-l',
                        dest='ofmt',
                        action='store_const',
                        const='libusb-c',
                        help='output libusb C (WARNING: experimental)')
    parser.add_argument('-p',
                        dest='ofmt',
                        action='store_const',
                        const='libusb-py',
                        help='output libusb python')
    parser.add_argument("--json",
                        '-j',
                        dest='ofmt',
                        action='store_const',
                        const='json',
                        help='output json')
    parser.add_argument('-s', help='allow short')
    parser.add_argument('-f', help='custom call')
    add_bool_arg(parser,
                 '--packet-numbers',
                 default=True,
                 help='print packet numbers')
    parser.add_argument('--verbose', '-v', action='store_true', help='verbose')
    parser.add_argument(
        '--parser',
        default="auto",
        help='Which parser engine to use. Choices: auto, lin-pcap, win-pcap')
    add_bool_arg(
        parser,
        '--sleep',
        default=False,
        help='Insert sleep statements between packets to keep original timing')
    add_bool_arg(parser, '--comment', default=False, help='General comments')
    add_bool_arg(parser, '--fx2', default=False, help='FX2 comments')
    add_bool_arg(parser,
                 '--define',
                 default=False,
                 help='Use defines instead of raw numbers')
    add_bool_arg(parser, '--halt', default=True, help='Halt on bad packets')
    parser.add_argument('--vid',
                        type=str,
                        default="0",
                        help='Only keep packets for given VID')
    parser.add_argument('--pid',
                        type=str,
                        default="0",
                        help='Only keep packets for given PID')
    parser.add_argument('--device',
                        type=int,
                        default=None,
                        help='Only keep packets for given device')
    add_bool_arg(parser,
                 '--device-hi',
                 default=None,
                 help='Auto detect to highest device number')
    add_bool_arg(parser,
                 '--rel-pkt',
                 default=False,
                 help='Only count kept packets')
    # http://sourceforge.net/p/libusb/mailman/message/25635949/
    add_bool_arg(parser,
                 '--remoteio',
                 default=False,
                 help='Warn on -EREMOTEIO resubmit (default: ignore)')
    add_bool_arg(
        parser,
        '--print-short',
        default=False,
        help='Print warning when request returns less data than requested')
    add_bool_arg(
        parser,
        '--setup',
        default=False,
        help='Emit initialization packets like CLEAR_FEATURE, SET_FEATURE')
    add_bool_arg(parser,
                 '--wrapper',
                 default=False,
                 help='Emit code to make it a full executable program')

    add_bool_arg(parser,
                 '--mpsee',
                 default=False,
                 help='Decode mpsee traffic (highly experimental)')
    add_bool_arg(parser, '--serial-emit-adata', default=True, help='')
    add_bool_arg(parser, '--serial-keep-raw-data', default=False, help='')
    add_bool_arg(parser, '--serial-keep-unused-data', default=False, help='')
    add_bool_arg(parser, '--serial-keep-empty-txrx', default=False, help='')

    parser.add_argument('fin', help='File name in')
    args = parser.parse_args()
    argsj = usbrply.main.munge_argsj(args)

    if args.verbose:
        print("")
        print("")
        print("")
        print("PASS: USB parse")
    parsed = usbrply.parsers.pcap2json(args.fin, argsj)
    filters = []
    filters.append("vidpid")
    if not args.setup:
        filters.append("setup")
    if args.comment or args.fx2:
        filters.append("commenter")
    filtered = usbrply.filters.run(filters,
                                   parsed,
                                   argsj,
                                   verbose=args.verbose)

    if args.verbose:
        print("")
        print("")
        print("")
        print("PASS: serial parse")
    j = parsers.jgen2j(filtered)

    fparser = sparsers.FT2232CParser

    txtj = fparser(argsj=argsj).run(j)

    printer = {
        'text': sprinters.TextFT2232CPrinter,
        'libusb-py': sprinters.PythonFT2232CPrinter,
        'json': sprinters.JSONSPrinter,
    }[args.ofmt]

    if args.verbose:
        print("")
        print("")
        print("")
        print("PASS: serial print")
    printer(argsj=argsj).run(txtj)

    if args.mpsee:
        if args.verbose:
            print("")
            print("")
            print("")
            print("PASS: MPSSE parse")
        mpssej = mpsse.MPSSEParser().run(txtj)
        if args.verbose:
            print("")
            print("")
            print("")
            print("PASS: MPSSE print")
        mpsse.MPSSETextPrinter(args).run(mpssej)


if __name__ == "__main__":
    main()
