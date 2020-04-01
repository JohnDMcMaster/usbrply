import argparse
from usbrply import usbrply
from usbrply.usbrply import add_bool_arg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Replay captured USB packets')
    parser.add_argument('--range', '-r', help='inclusive range like 123:456')
    parser.add_argument('-k', dest='ofmt', default='libusbpy', action='store_const', const='linux', help='output linux kenrel')
    parser.add_argument('-l', dest='ofmt', action='store_const', const='libusb', help='output libusb')
    parser.add_argument('-p', dest='ofmt', action='store_const', const='libusbpy', help='output libusb python')
    parser.add_argument('-j', dest='ofmt', action='store_const', const='json', help='output json')
    parser.add_argument('-s', help='allow short')
    parser.add_argument('-f', help='custom call')
    add_bool_arg(parser, '--packet-numbers', default=True, help='print packet numbers') 
    parser.add_argument('--bulk-dir', help='bulk data .bin dir')
    parser.add_argument('--verbose', '-v', action='store_true', help='verbose')
    add_bool_arg(parser, '--sleep', default=False, help='Insert sleep statements between packets to keep original timing')
    add_bool_arg(parser, '--comment', default=False, help='General comments')
    add_bool_arg(parser, '--fx2', default=False, help='FX2 comments')
    add_bool_arg(parser, '--define', default=False, help='Use defines instead of raw numbers')
    add_bool_arg(parser, '--halt', default=True, help='Halt on errors')
    add_bool_arg(parser, '--cc', default=False, help='Custom call output')
    parser.add_argument('--device', type=int, default=None, help='Only keep packets for given device')
    parser.add_argument('--device-hi', action='store_true', help='Auto detect to highest device number')
    add_bool_arg(parser, '--rel-pkt', default=False, help='Only count kept packets')
    # http://sourceforge.net/p/libusb/mailman/message/25635949/
    add_bool_arg(parser, '--remoteio', default=False, help='Warn on -EREMOTEIO resubmit (default: ignore)')
    add_bool_arg(parser, '--print-short', default=False, help='Print warning when request returns less data than requested')
    add_bool_arg(parser, '--setup', default=False, help='Emit initialization packets like CLEAR_FEATURE, SET_FEATURE')
    add_bool_arg(parser, '--wrapper', default=False, help='Emit code to make it a full executable program')
    parser.add_argument('--vid', default='0')
    parser.add_argument('--pid', default='0')
    parser.add_argument('fin', help='File name in')
    args = parser.parse_args()
    usbrply.args = args

    vid = int(args.vid, 0)
    pid = int(args.pid, 0)

    if args.range:
        (usbrply.g_min_packet, g_max_packet) = args.range.split(':')
        if len(usbrply.g_min_packet) == 0:
            usbrply.g_min_packet = 0
        else:
            usbrply.g_min_packet = int(usbrply.g_min_packet, 0)
        if len(g_max_packet) == 0:
            usbrply.g_max_packet = float('inf')
        else:
            usbrply.g_max_packet = int(usbrply.g_max_packet, 0)
    
    if args.bulk_dir:
        args.ofmt = 'bin'
        os.mkdir(args.bulk_dir)

    gen = usbrply.Gen()
    gen.run()
