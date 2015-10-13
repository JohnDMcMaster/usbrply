import re
import sys
import ast
import json
import binascii

prefix = ' ' * 8

def str2hex(buff, prefix='', terse=True):
    buff = bytearray(buff)
    ret = ''
    if terse and len(buff) > 16:
        ret += '\n'
    for i in xrange(len(buff)):
        if i % 16 == 0:
            if i != 0:
                ret += '" \\\n'
            if len(buff) <= 16:
                ret += '"'
            if not terse or len(buff) > 16:
                ret += '%s"' % prefix
            
        ret += "\\x%02X" % (buff[i],)
    return ret + '"'

def fmt_terse(data):
    ret = str2hex(data, prefix=prefix)
    if len(data) > 16:
        ret += '\n%s' % prefix
    return ret

def dump(fin):
    j = json.load(open(fin))
    pi = 0
    ps = j['data']
    while pi < len(ps):
        p = ps[pi]
        if p['type'] == 'comment':
            #print '# %s' % p['v']
            pass
        elif p['type'] == 'controlRead':
            '''
            # Generated from packet 6/7
            # None (0xB0)
            buff = controlRead(0xC0, 0xB0, 0x0000, 0x0000, 4096)
            # NOTE:: req max 4096 but got 3
            validate_read("\x00\x00\x00", buff, "packet 6/7")
            '''
            print 'buff = controlRead(0x%02X, 0x%02X, 0x%04X, 0x%04X, %d)' % (
                    p['req'], p['reqt'], p['val'], p['ind'], p['len'])
            data = binascii.unhexlify(p['data'])
            print '# Req: %d, got: %d' % (p['len'], len(data))
            print 'validate_read(%s, buff, "packet %d/%d")' % (
                    fmt_terse(data), p['packn'][0], p['packn'][1])
        elif p['type'] == 'controlWrite':
            '''
            controlWrite(0x40, 0xB2, 0x0000, 0x0000, "")
            '''
            data = binascii.unhexlify(p['data'])
            print 'buff = controlWrite(0x%02X, 0x%02X, 0x%04X, 0x%04X, %s)' % (
                    p['req'], p['reqt'], p['val'], p['ind'], str2hex(data, prefix=prefix))
        elif p['type'] == 'bulkRead':
            '''
            buff = bulkRead(0x86, 0x0200)
            # NOTE:: req max 512 but got 4
            validate_read("\x08\x16\x01\x00", buff, "packet 8/9")
            '''
            print 'buff = bulkRead(0x%02X, 0x%04X)' % (p['endp'], p['len'])
            data = binascii.unhexlify(p['data'])
            print '# Req: %d, got: %d' % (p['len'], len(data))
            print 'validate_read(%s, buff, "packet %d/%d")' % (
                    fmt_terse(data), p['packn'][0], p['packn'][1])
        elif p['type'] == 'bulkWrite':
            '''
            bulkWrite(0x02, "\x01")
            '''
            data = binascii.unhexlify(p['data'])
            print 'bulkWrite(0x%02X, %s)' % (p['endp'], str2hex(data, prefix=' '*8))
        else:
            raise Exception("Unknown type: %s" % p['type'])
        pi += 1
if __name__ == "__main__":
    import argparse 
    
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('fin')
    args = parser.parse_args()
    dump(args.fin)
