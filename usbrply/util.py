import sys
import subprocess
import json
from collections import OrderedDict
import binascii


def clear_screen():
    # 00000000  1b 5b 33 3b 4a 1b 5b 48  1b 5b 32 4a              |.[3;J.[H.[2J|
    sys.stdout.write("\x1b\x5b\x33\x3b\x4a\x1b\x5b\x48\x1b\x5b\x32\x4a")
    sys.stdout.flush()


def hexdump(data, label=None, indent='', address_width=8, f=sys.stdout):
    def isprint(c):
        return c >= ' ' and c <= '~'

    if label:
        print(label)

    bytes_per_half_row = 8
    bytes_per_row = 16
    data = bytearray(data)
    data_len = len(data)

    def hexdump_half_row(start):
        left = max(data_len - start, 0)

        real_data = min(bytes_per_half_row, left)

        f.write(''.join('%02X ' % c for c in data[start:start + real_data]))
        f.write(''.join('   ' * (bytes_per_half_row - real_data)))
        f.write(' ')

        return start + bytes_per_half_row

    pos = 0
    while pos < data_len:
        row_start = pos
        f.write(indent)
        if address_width:
            f.write(('%%0%dX  ' % address_width) % pos)
        pos = hexdump_half_row(pos)
        pos = hexdump_half_row(pos)
        f.write("|")
        # Char view
        left = data_len - row_start
        real_data = min(bytes_per_row, left)

        f.write(''.join([
            c if isprint(c) else '.'
            for c in tostr(data[row_start:row_start + real_data])
        ]))
        f.write((" " * (bytes_per_row - real_data)) + "|\n")


def add_bool_arg(parser, yes_arg, default=False, **kwargs):
    dashed = yes_arg.replace('--', '')
    dest = dashed.replace('-', '_')
    parser.add_argument(yes_arg,
                        dest=dest,
                        action='store_true',
                        default=default,
                        **kwargs)
    kwargs['help'] = 'Disable above'
    parser.add_argument('--no-' + dashed,
                        dest=dest,
                        action='store_false',
                        **kwargs)


# In Python2 bytes_data is a string, in Python3 it's bytes.
# The element type is different (string vs int) and we have to deal
# with that when printing this number as hex.
if sys.version_info[0] == 2:
    myord = ord
else:
    myord = lambda x: x


def tobytes(buff):
    if type(buff) is str:
        #return bytearray(buff, 'ascii')
        return bytearray([myord(c) for c in buff])
    elif type(buff) is bytearray or type(buff) is bytes:
        return buff
    else:
        assert 0, type(buff)


def tostr(buff):
    if type(buff) is str:
        return buff
    elif type(buff) is bytearray or type(buff) is bytes:
        return ''.join([chr(b) for b in buff])
    else:
        assert 0, type(buff)


def isprint(c):
    return c >= ' ' and c <= '~'


def to_pintable_str(buff):
    buff = tostr(buff)
    return "".join([c for c in buff if isprint(c)])


# Used by scraper scripts
# Due to python2 vs python3 issue, its better to subprocess this
def load_pcap_json(fin, usbrply_args=""):
    if fin.find('.cap') >= 0 or fin.find('.pcapng') >= 0:
        json_fn = '/tmp/scrape.json'
        cmd = 'usbrply %s  --json %s >%s' % (usbrply_args, fin, json_fn)
        subprocess.check_call(cmd, shell=True)
    else:
        json_fn = fin

    j = json.load(open(json_fn))
    return j, json_fn


"""
Common issues:
-Bytes
-Bytearray
"""


def validate_json(j, prefix="top"):
    ret = True
    if type(j) in (str, int, float):
        return True
    elif j is None:
        return True
    elif type(j) in (OrderedDict, dict):
        for k, v in j.items():
            ok = validate_json(k, prefix=prefix + " key")
            ret = ok and ret
            if ok:
                ret = validate_json(v, prefix=prefix + "[m %s]" % k) and ret
    elif type(j) in (tuple, list):
        for vi, v in enumerate(j):
            ret = validate_json(v, prefix=prefix + "[l %u]" % vi) and ret
        return True
    else:
        print("json @ %s: unexpected type %s" % (prefix, type(j)))
        return False
    return ret


def hex_jdata(jdata):
    """
    Some packets get converted to bytes/bytearray when parsing
    Convert them back for storage
    """
    if type(jdata) in (dict, OrderedDict):
        ret = {}
        for k, v in jdata.items():
            ret[k] = hex_jdata(v)
        return ret
    elif type(jdata) in (list, tuple):
        for vi, v in enumerate(jdata):
            jdata[vi] = hex_jdata(v)
        return jdata
    elif type(jdata) in (bytes, bytearray):
        return tostr(binascii.hexlify(jdata))
    else:
        return jdata
