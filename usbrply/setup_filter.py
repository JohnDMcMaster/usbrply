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
    def __init__(self, argsj):
        # self.setup = argsj.get("setup", False)
        pass

    def should_filter(self, data):
        return req2s(data["bRequestType"], data["bRequest"]) in setup_reqs

    def gen_data(self, datas):
        for data in datas:
            if data["type"] in ("controlWrite",
                                "controlRead") and self.should_filter(data):
                continue
            yield data

    def run(self, jgen):
        for k, v in jgen:
            if k == "data":
                yield k, self.gen_data(v)
            else:
                yield k, v
