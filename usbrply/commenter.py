from .usb import req2s, feat_i2s
import binascii


class Commenter(object):
    def __init__(self, argsj, verbose=False):
        self.fx2 = argsj.get("fx2", False)
        self.verbose = verbose

    # FX2 regs: http://www.keil.com/dd/docs/datashts/cypress/fx2_trm.pdf
    # FX2LP regs: http://www.cypress.com/file/126446/download
    def try_comment(self, data):
        # Table 9-3. Standard Device Requests
        vendor = None
        if self.fx2:
            vendor = {
                0xA0: "FX2_REG_W",
            }
        reqs = req2s(data["bRequestType"], data["bRequest"], vendor)
        if not reqs:
            return

        ret = '%s (0x%02X)' % (reqs, data["bRequest"])
        if reqs == 'SET_ADDRESS':
            ret += ': 0x%02x/%d' % (data["wValue"], data["wValue"])
        elif reqs == 'SET_FEATURE' or reqs == 'CLEAR_FEATURE':
            ret += ': 0x%02X (%s)' % (data["wValue"],
                                      feat_i2s.get(data["wValue"], 'unknown'))
        elif reqs == 'FX2_REG_W':
            addr = data["wValue"]
            reg2s = {
                0xE600: 'CPUCS',
            }
            reg = reg2s.get(addr, None)

            # 5.4 FX2 Memory Maps
            # Appendix C
            # FX2 Register Summary
            ret += ': addr=0x%04X' % (data["wValue"])
            if reg:
                ret += ' (%s)' % (reg, )
            elif addr < 0x1000:
                ret += ' (FW load)'
            # FX2: 8K of on-chip RAM (the "Main RAM") at addresses 0x0000-0x1FFF
            # FX2LP: 16K
            elif 0x0000 <= addr <= 0x3FFF:
                ret += ' (main RAM addr=0x%04X)' % addr
            # 512 bytes of on-chip RAM (the "Scratch RAM") at addresses 0xE000-0xE1FFF
            elif 0xE000 <= addr <= 0xE1FF:
                ret += ' (scratch RAM)'
            # The CPU communicates with the SIE using a set of registers occupying on-chip RAM addresses 0xE600-0xE6FF"
            elif 0xE600 <= addr <= 0xE6FF:
                ret += ' (unknown reg)'
            # per memory map: 7.5KB of USB regs and 4K EP buffers
            elif 0xE200 <= addr <= 0xFFFF:
                ret += ' (unknown misc)'
            else:
                ret += ' (unknown)'

            bdat = binascii.unhexlify(data["data"])
            if len(bdat) == 1:
                dat = ord(bdat)
                if reg == 'CPUCS':
                    if dat & 1 == 1:
                        ret += ', reset: hold'
                    else:
                        ret += ', reset: release'
        l = data.get("comments", [])
        l.append(ret)
        data["comments"] = l

    def gen_data(self, datas):
        for data in datas:
            if data["type"] in ("controlWrite", "controlRead"):
                self.try_comment(data)
            yield data

    def run(self, jgen):
        for k, v in jgen:
            if k == "data":
                yield k, self.gen_data(v)
            else:
                yield k, v
