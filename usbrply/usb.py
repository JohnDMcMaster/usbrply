'''
possible transfer mode
'''
URB_TRANSFER_IN = 0x80
URB_ISOCHRONOUS = 0x0
URB_INTERRUPT = 0x1
URB_CONTROL = 0x2
URB_BULK = 0x3
'''
possible event type
'''
URB_SUBMIT = ord('S')
URB_COMPLETE = ord('C')
URB_ERROR = ord('E')

urb_type2str = {
    URB_SUBMIT: 'URB_SUBMIT',
    URB_COMPLETE: 'URB_COMPLETE',
    URB_ERROR: 'URB_ERROR',
}

USB_REQ_GET_STATUS = 0x00
USB_REQ_CLEAR_FEATURE = 0x01
# 0x02 is reserved
USB_REQ_SET_FEATURE = 0x03
# 0x04 is reserved
USB_REQ_SET_ADDRESS = 0x05
USB_REQ_GET_DESCRIPTOR = 0x06
USB_REQ_SET_DESCRIPTOR = 0x07
USB_REQ_GET_CONFIGURATION = 0x08
USB_REQ_SET_CONFIGURATION = 0x09
USB_REQ_GET_INTERFACE = 0x0A
USB_REQ_SET_INTERFACE = 0x0B
USB_REQ_SYNCH_FRAME = 0x0C

USB_DIR_OUT = 0  # to device
USB_DIR_IN = 0x80  # to host

USB_TYPE_MASK = (0x03 << 5)
USB_TYPE_STANDARD = (0x00 << 5)  # 0x00
USB_TYPE_CLASS = (0x01 << 5)  # 0x20
USB_TYPE_VENDOR = (0x02 << 5)  # 0x40
USB_TYPE_RESERVED = (0x03 << 5)  # 0x60

USB_RECIP_MASK = 0x1f
USB_RECIP_DEVICE = 0x00
USB_RECIP_INTERFACE = 0x01
USB_RECIP_ENDPOINT = 0x02
USB_RECIP_OTHER = 0x03
# From Wireless USB 1.0
USB_RECIP_PORT = 0x04
USB_RECIP_RPIPE = 0x05

# Table 9-6. Standard Feature Selectors
feat_i2s = {
    # Endpoint
    0: 'ENDPOINT_HALT',
    # Device
    1: 'DEVICE_REMOTE_WAKEUP',
    # Device
    2: 'TEST_MODE',
}

setup_reqs = [
    # reply type
    #"GET_STATUS",
    "CLEAR_FEATURE",
    "SET_FEATURE",
    "SET_ADDRESS",
    "GET_DESCRIPTOR",
    "SET_DESCRIPTOR",
    "GET_CONFIGURATION",
    "SET_CONFIGURATION",
    "SET_INTERFACE",
    "GET_INTERFACE",
    "CLEAR_FEATURE",
    "SYNCH_FRAME",
]


def req2s(ctrl, fx2=False):
    m = {
        USB_TYPE_STANDARD: {
            USB_REQ_GET_STATUS: "GET_STATUS",
            USB_REQ_CLEAR_FEATURE: "CLEAR_FEATURE",
            USB_REQ_SET_FEATURE: "SET_FEATURE",
            USB_REQ_SET_ADDRESS: "SET_ADDRESS",
            USB_REQ_GET_DESCRIPTOR: "GET_DESCRIPTOR",
            USB_REQ_SET_DESCRIPTOR: "SET_DESCRIPTOR",
            USB_REQ_GET_CONFIGURATION: "GET_CONFIGURATION",
            USB_REQ_SET_CONFIGURATION: "SET_CONFIGURATION",
            USB_REQ_SET_INTERFACE: "SET_INTERFACE",
        },
        USB_TYPE_CLASS: {
            USB_REQ_GET_STATUS: "GET_STATUS",
            USB_REQ_CLEAR_FEATURE: "CLEAR_FEATURE",
            USB_REQ_SET_FEATURE: "SET_FEATURE",
            USB_REQ_GET_INTERFACE: "GET_INTERFACE",
        },
        USB_TYPE_VENDOR: {
            USB_REQ_GET_STATUS: "GET_STATUS",
            USB_REQ_SET_FEATURE: "SET_FEATURE",
            USB_REQ_CLEAR_FEATURE: "CLEAR_FEATURE",
            USB_REQ_SYNCH_FRAME: "SYNCH_FRAME",
        },
    }
    if fx2:
        m[USB_TYPE_VENDOR].update({
            0xA0: "FX2_REG_W",
        })

    reqType = ctrl.bRequestType & USB_TYPE_MASK
    n = m.get(reqType, None)
    if n is None or not ctrl.bRequest in n:
        return None
    reqs = n[ctrl.bRequest]
    return reqs


def request_type2str(bRequestType):
    ret = ""

    if (bRequestType & USB_DIR_IN) == USB_DIR_IN:
        ret += "USB_DIR_IN"
    else:
        ret += "USB_DIR_OUT"

    m = {
        USB_TYPE_STANDARD: " | USB_TYPE_STANDARD",
        USB_TYPE_CLASS: " | USB_TYPE_CLASS",
        USB_TYPE_VENDOR: " | USB_TYPE_VENDOR",
        USB_TYPE_RESERVED: " | USB_TYPE_RESERVED",
    }
    ret += m[bRequestType & USB_TYPE_MASK]

    m = {
        USB_RECIP_DEVICE: " | USB_RECIP_DEVICE",
        USB_RECIP_INTERFACE: " | USB_RECIP_INTERFACE",
        USB_RECIP_ENDPOINT: " | USB_RECIP_ENDPOINT",
        USB_RECIP_OTHER: " | USB_RECIP_OTHER",
        USB_RECIP_PORT: " | USB_RECIP_PORT",
        USB_RECIP_RPIPE: " | USB_RECIP_RPIPE",
    }
    ret += m[bRequestType & USB_RECIP_MASK]

    return ret


transfer2str = {
    URB_ISOCHRONOUS: "URB_ISOCHRONOUS",
    URB_INTERRUPT: "URB_INTERRUPT",
    URB_CONTROL: "URB_CONTROL",
    URB_BULK: "URB_BULK",
}


def transfer2str_safe(t):
    return transfer2str.get(t, "UNKNOWN_%02x" % t)


# FX2 regs: http://www.keil.com/dd/docs/datashts/cypress/fx2_trm.pdf
# FX2LP regs: http://www.cypress.com/file/126446/download
def req_comment(ctrl, dat):
    # Table 9-3. Standard Device Requests
    reqs = req2s(ctrl)
    if not reqs:
        return
    ret = '%s (0x%02X)' % (reqs, ctrl.bRequest)
    if reqs == 'SET_ADDRESS':
        ret += ': 0x%02x/%d' % (ctrl.wValue, ctrl.wValue)
    elif reqs == 'SET_FEATURE' or reqs == 'CLEAR_FEATURE':
        ret += ': 0x%02X (%s)' % (ctrl.wValue,
                                  feat_i2s.get(ctrl.wValue, 'unknown'))
    elif reqs == 'FX2_REG_W':
        addr = ctrl.wValue
        reg2s = {
            0xE600: 'CPUCS',
        }
        reg = reg2s.get(addr, None)

        # 5.4 FX2 Memory Maps
        # Appendix C
        # FX2 Register Summary
        ret += ': addr=0x%04X' % (ctrl.wValue)
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

        if len(dat) == 1:
            dat = ord(dat)
            if reg == 'CPUCS':
                if dat & 1 == 1:
                    ret += ', reset: hold'
                else:
                    ret += ', reset: release'
    comment(ret)
