import sys


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
            for c in str(data[row_start:row_start + real_data])
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
