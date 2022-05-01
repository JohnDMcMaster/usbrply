"""
Parses raw FTDI calls into higher level MPSSE info

If a bad command is detected, the MPSSE returns the value 0xFA, followed by the byte that caused the
bad command.

Use of the bad command detection is the recommended method of determining whether the MPSSE is in
sync with the application program. By sending a bad command on purpose and looking for 0xFA, the
application can determine whether communication with the MPSSE is possible.
"""

import binascii
import json

mpsse_cmd_s2i = {
    # think values < 0x10 are bit bang?

    # 3.3 MSB FIRST
    "MSB_DOUT_BYTES_PVE": 0x10,
    "MSB_11": 0x11,
    "MSB_12": 0x12,
    "MSB_13": 0x13,
    "MSB_20": 0x20,
    "MSB_24": 0x24,
    "MSB_22": 0x22,
    "MSB_26": 0x26,
    "MSB_31": 0x31,
    "MSB_34": 0x34,
    "MSB_33": 0x33,
    "MSB_36": 0x36,

    # 3.4 LSB FIRST
    "LSB_18": 0x18,
    "LSB_19": 0x19,
    "LSB_1A": 0x1A,
    "LSB_1B": 0x1B,
    "LSB_28": 0x28,
    "LSB_2C": 0x2C,
    "LSB_2A": 0x2A,
    "LSB_2E": 0x2E,
    "LSB_39": 0x39,
    "LSB_3C": 0x3C,
    "LSB_3B": 0x3B,
    "LSB_3E": 0x3E,

    # 3.5 TMS Commands
    "TMS_4A": 0x4A,
    "TMS_4B": 0x4B,
    "TMS_6A": 0x6A,
    "TMS_6B": 0x6B,
    "TMS_6E": 0x6E,
    "TMS_6F": 0x6F,

    # 3.6 Set / Read Data Bits High / Low Bytes
    "SETRDBHLB_80": 0x80,
    "SETRDBHLB_82": 0x82,
    "SETRDBHLB_81": 0x81,
    "SETRDBHLB_83": 0x83,

    # 3.7 Loopback Commands
    "LOOPBACK_EN": 0x84,
    "LOOPBACK_DIS": 0x85,

    # 3.8 Clock Divisor
    # 3.8.1 Set TCK/SK Divisor (FT2232D)
    # 3.8.2 Set clk divisor (FT232H/FT2232H/FT4232H)
    "SET_TCKSK_DIV": 0x86,

    # 4 Instructions for CPU mode
    # 4.2 CPUMode Read Short Address
    "CPU_90": 0x90,
    # 4.3 CPUMode Read Extended Address
    "CPU_91": 0x91,
    # 4.4 CPUMode Write Short Address
    "CPU_92": 0x92,
    # 4.5 CPUMode Write Extended Address
    "CPU_93": 0x93,

    # 5 Instructions for use in both MPSSE and MCU Host Emulation Modes
    # 5.1 Send Immediate
    "SEND_IMMEDIATE": "0x87",
    # 5.2 Wait On I/O High
    "WAIT_IO_HI": "0x88",
    # 5.3 Wait On I/O Low
    "WAIT_IO_LO": "0x89",

    # 6 FT232H, FT2232H & FT4232H ONLY

    # Disables the clk divide by 5 to allow for a 60MHz master clock.
    "TCK_X5": 0x8A,
    # Enables the clk divide by 5 to allow for backward compatibility with FT2232D
    "TCK_D5": 0x8B,
    # Enables 3 phase data clocking. Used by I 2 C interfaces to allow data on both clock edges.
    "ENABLE_3_PHASE_CLOCK": 0x8C,
    # Disables 3 phase data clocking.
    "DISABLE_3_PHASE_CLOCK": 0x8D,
    "CLOCK_N_CYCLES": 0x8E,
    "CLOCK_N8_CYCLES": 0x8F,
    "PULSE_CLOCK_IO_HIGH": 0x94,
    "PULSE_CLOCK_IO_LOW": 0x95,
    "ENABLE_ADAPTIVE_CLOCK": 0x96,
    "DISABLE_ADAPTIVE_CLOCK": 0x97,
    "CLOCK_N8_CYCLES_IO_HIGH": 0x9C,
    "CLOCK_N8_CYCLES_IO_LOW": 0x9D,

    # 7 FT232H ONLY
    # 7.1 Set I/O to only drive on a '0' and tristate on a '1'
    "TRISTATE_IO": 0x9E,

    # basically a nop for testing interface
    "INVALID_COMMAND": 0xAB,
}
mpsse_cmd_i2s = dict([(v, k) for k, v in mpsse_cmd_s2i.items()])

BAD_COMMAND = 0xFA

"""
Ingests Serial JSON
"""
class MPSSEParser:
    def __init__(self, argsj=None):
        self.jo = []

    def next_json(self, j, prefix=None):
        self.jo.append(j)

    def handleRead(self, d):
        print(d['data'])
        buff = bytearray(binascii.unhexlify(d['data']))
        if buff[0] == BAD_COMMAND:
            which = mpsse_cmd_i2s.get(buff[1], None)
            print("read invalid: %s" % which)
        else:
            print("read 0x%02X" % (buff[0], ))

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


class MPSSETextPrinter:
    def __init__(self, argsj=None):
        pass

    def next_json(self, j, prefix=None):
        print(j)

    def run(self, j):
        #self.header()

        for d in j["data"]:
            self.next_json(d)

        #self.footer()


class MPSSEJSONSPrinter:
    def __init__(self, argsj=None):
        pass

    def run(self, j):
        print(json.dumps(j, sort_keys=True, indent=4, separators=(',', ': ')))
