'''
possible transfer mode
'''
URB_TRANSFER_IN = 0x80
URB_ISOCHRONOUS = 0x0
URB_INTERRUPT = 0x1
URB_CONTROL = 0x2
URB_BULK = 0x3
# Wireshark GUI's name
USB_IRP_INFO = 0xFE
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

USB_TYPE_MASK = (0x03 << 5)  # 0x60
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


def req2s(bRequestType, bRequest, vendor=None):
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
        # 2020-12-29: these are interfering with a device
        # Leave these out for now, try to figure out why they were added
        # and more concretely document
        # USB_TYPE_VENDOR: {
        #    USB_REQ_GET_STATUS: "GET_STATUS",
        #    USB_REQ_SET_FEATURE: "SET_FEATURE",
        #    USB_REQ_CLEAR_FEATURE: "CLEAR_FEATURE",
        #    USB_REQ_SYNCH_FRAME: "SYNCH_FRAME",
        #},
    }
    if vendor:
        m[USB_TYPE_VENDOR].update(vendor)

    reqType = bRequestType & USB_TYPE_MASK
    n = m.get(reqType, None)
    if n is None or not bRequest in n:
        return None
    reqs = n[bRequest]
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
