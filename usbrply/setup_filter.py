from .usb import req2s

setup_reqs = [
    # reply type
    "GET_STATUS",
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


class SetupFilter(object):
    def __init__(self, argsj, verbose=False):
        # self.setup = argsj.get("setup", False)
        self.verbose = verbose
        self.entries = 0
        self.drops = 0

    def should_filter(self, data):
        return req2s(data["bRequestType"], data["bRequest"]) in setup_reqs

    def gen_data(self, datas):
        for data in datas:
            self.entries += 1
            if data["type"] in ("controlWrite",
                                "controlRead") and self.should_filter(data):
                if self.verbose:
                    print("SetupFilter drop %s (%s %s %s)" %
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
            "SetupFilter: dropped %s / %s entries" % (self.drops, self.entries)
        }

    def run(self, jgen):
        for k, v in jgen:
            if k == "data":
                yield k, self.gen_data(v)
            else:
                yield k, v
