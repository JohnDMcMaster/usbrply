"""
Parses raw FTDI calls into higher level MPSSE info

If a bad command is detected, the MPSSE returns the value 0xFA, followed by the byte that caused the
bad command.

Use of the bad command detection is the recommended method of determining whether the MPSSE is in
sync with the application program. By sending a bad command on purpose and looking for 0xFA, the
application can determine whether communication with the MPSSE is possible.
"""

import binascii 

mpsse_cmd_s2i = {
    "INVALID_COMMAND": 0xAB,
    "ENABLE_ADAPTIVE_CLOCK": 0x96,
    "DISABLE_ADAPTIVE_CLOCK": 0x97,
    "ENABLE_3_PHASE_CLOCK": 0x8C,
    "DISABLE_3_PHASE_CLOCK": 0x8D,
    "TCK_X5": 0x8A,
    "TCK_D5": 0x8B,
    "CLOCK_N_CYCLES": 0x8E,
    "CLOCK_N8_CYCLES": 0x8F,
    "PULSE_CLOCK_IO_HIGH": 0x94,
    "PULSE_CLOCK_IO_LOW": 0x95,
    "CLOCK_N8_CYCLES_IO_HIGH": 0x9C,
    "CLOCK_N8_CYCLES_IO_LOW": 0x9D,
    "TRISTATE_IO":          0x9E,
}
mpsse_cmd_i2s = dict([(v, k) for k, v in mpsse_cmd_s2i.items()])

class MPSSEParser(object):
    def __init__(self):
        self.jo = []

    def next_json(self, j, prefix=None):
        self.jo.append(j)

    def handleRead(self, d):
        pass

    def handleWrite(self, d):
        print(d['data'])
        buff = bytearray(binascii.unhexlify(d['data']))
        cmd = mpsse_cmd_i2s.get(buff[0], None)
        print(cmd)

    def run(self, j):
        for di, d in enumerate(j["data"]):
            print("")
            print(d)
            if d['type'] == 'read':
                self.handleRead(d)
            elif d['type'] == 'write':
                self.handleWrite(d)
            else:
                print('fixme: %s' % d['type'])

        jret = {
            "data": self.jo,
        }
        return jret


class MPSSETextPrinter(object):
    def __init__(self, args):
        self.ascii = args.ascii

    def next_json(self, j, prefix=None):
        print(j)

    def run(self, j):
        #self.header()

        for d in j["data"]:
            self.next_json(d)

        #self.footer()

class MPSSEJSONSPrinter(object):
    def __init__(self, args):
        self.ascii = args.ascii

    def run(self, j):
        print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))
