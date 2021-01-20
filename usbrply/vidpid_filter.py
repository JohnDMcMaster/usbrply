from .usb import req2s
import binascii
import struct
from .util import hexdump


def default_arg(argsj, k, default):
    val = argsj.get(k)
    if val is None:
        return default
    else:
        return val


class VidpidFilter(object):
    def __init__(self, argsj, verbose=False):
        # self.setup = argsj.get("setup", False)
        self.verbose = verbose
        self.entries = 0
        self.drops = 0

        self.arg_vid = default_arg(argsj, "vid", None)
        self.arg_pid = default_arg(argsj, "pid", None)
        self.device2vidpid = {}
        self.keep_device = None

    def should_filter(self, data):
        return False

        if self.arg_vid is None and self.arg_pid is None:
            return False

        device = data.get('device')
        # a new vid/pid mapping?
        # if data["type"] == "controlRead" and req2s(data["bRequestType"], data["bRequest"]) == "GET_DESCRIPTOR" and data["bDescriptorType"] == 0x01:
        # FIXME: hack
        buff = binascii.unhexlify(data.get("data", ""))
        if data["type"] == "controlRead" and req2s(
                data["bRequestType"],
                data["bRequest"]) == "GET_DESCRIPTOR" and len(buff) == 0x12:
            print(data)
            # not actually decoded
            print("buf", len(buff))
            hexdump(buff)
            # TODO: parse this more genericly
            vid, pid = struct.unpack("<HH", buff[0x08:0x0C])
            print("VID PID 0x%04X 0x%04X" % (vid, pid))
            self.device2vidpid[device] = (vid, pid)
            if (vid == self.arg_vid
                    or self.arg_vid is None) or (pid == self.arg_pid
                                                 or self.arg_pid is None):
                print("hit")
                if self.keep_device is not None:
                    print("WARNING: already had device")
                self.keep_device = device
            return False

        # Filter:
        # Devices not matching target
        # Anything before we've established mapping. Most of this traffic isn't important and simplifies parser
        return device is not None and device == self.keep_device

    def gen_data(self, datas):
        for data in datas:
            self.entries += 1
            if self.should_filter(data):
                if self.verbose:
                    print("VidpidFilter drop %s (%s %s %s)" %
                          (data['type'],
                           req2s(data["bRequestType"], data["bRequest"]),
                           data["bRequestType"], data["bRequest"]))
                self.drops += 1
                continue
            yield data
        yield {
            "type":
            "comment",
            "v":
            "VidpidFilter: dropped %s / %s entries" %
            (self.drops, self.entries)
        }

    def run(self, jgen):
        for k, v in jgen:
            if k == "data":
                yield k, self.gen_data(v)
            else:
                yield k, v
