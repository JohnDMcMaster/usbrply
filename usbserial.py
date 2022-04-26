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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decode USB-serial data')
    parser.add_argument('--range', '-r', help='inclusive range like 123:456')
    parser.add_argument('--verbose', '-v', action='store_true', help='verbose')
    add_bool_arg(
        parser,
        '--sleep',
        default=False,
        help='Insert sleep statements between packets to keep original timing')
    add_bool_arg(parser, '--comment', default=False, help='General comments')
    add_bool_arg(parser, '--ascii', default=False, help='Print as ASCII')
    parser.add_argument('-p',
                        dest='ofmt',
                        default='libusb-py',
                        action='store_const',
                        const='libusb-py',
                        help='output libusb python')
    parser.add_argument('-t',
                        dest='ofmt',
                        action='store_const',
                        const='text',
                        help='output text')
    parser.add_argument('-j',
                        dest='ofmt',
                        action='store_const',
                        const='json',
                        help='output json')
    parser.add_argument('--device',
                        type=int,
                        default=None,
                        help='Only keep packets for given device')
    parser.add_argument('--device-hi',
                        action='store_true',
                        help='Auto detect to highest device number')
    parser.add_argument('--vid', default='0')
    parser.add_argument('--pid', default='0')
    parser.add_argument('fin', help='File name in')
    parser.add_argument('-w', action='store_true', help='Write python file')

    parser.add_argument(
        '--parser',
        default="auto",
        help='Which parser engine to use. Choices: auto, lin-pcap, win-pcap')
    add_bool_arg(
        parser,
        '--setup',
        default=False,
        help='Emit initialization packets like CLEAR_FEATURE, SET_FEATURE')
    add_bool_arg(parser, '--wrapper', default=False, help='')
    add_bool_arg(parser, '--fx2', default=False, help='FX2 comments')
    add_bool_arg(parser,
                 '--rel-pkt',
                 default=False,
                 help='Only count kept packets')
    add_bool_arg(parser,
                 '--packet-numbers',
                 default=True,
                 help='print packet numbers')
    add_bool_arg(parser,
                 '--remoteio',
                 default=False,
                 help='Warn on -EREMOTEIO resubmit (default: ignore)')
    add_bool_arg(
        parser,
        '--print-short',
        default=False,
        help='Print warning when request returns less data than requested')
    add_bool_arg(parser,
                 '--mpsee',
                 default=False,
                 help='Decode mpsee traffic (highly experimental)')

    args = parser.parse_args()
    argsj = usbrply.main.munge_argsj(args)

    parser = sparsers.FT2232CParser
    printer = {
        'text': sprinters.TextFT2232CPrinter,
        'libusb-py': sprinters.PythonFT2232CPrinter,
        'json': sprinters.JSONSPrinter,
    }[args.ofmt]

    print("")
    print("")
    print("")
    print("PASS: USB parse")
    usbj = parsers.jgen2j(usbrply.parsers.pcap2json(args.fin, argsj))

    print("")
    print("")
    print("")
    print("PASS: serial parse")
    txtj = parser(args).run(usbj)

    print("")
    print("")
    print("")
    print("PASS: serial print")
    printer(args).run(txtj)

    if args.mpsee:
        print("")
        print("")
        print("")
        print("PASS: MPSSE parse")
        mpssej = mpsse.MPSSEParser().run(txtj)
        print("")
        print("")
        print("")
        print("PASS: MPSSE print")
        mpsse.MPSSETextPrinter(args).run(mpssej)
