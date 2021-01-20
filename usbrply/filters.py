from .commenter import Commenter
from .setup_filter import SetupFilter
from .vidpid_filter import VidpidFilter
# from .device_filter import DeviceFilter
from .parsers import jgen2j

filters = {
    "commenter": Commenter,
    "setup": SetupFilter,
    "vidpid": VidpidFilter,
    # "device": DeviceFilter,
}


def run(filts, jgen, argsj={}, verbose=False):
    """
    Run series of given filters on input jgen
    First filter in array is applied first
    """
    if len(filts) == 0:
        return jgen

    filt0 = filts[0]
    cls = filters[filt0]
    return run(filts[1:], cls(argsj).run(jgen), argsj=argsj, verbose=verbose)


# FIXME: loaded data is not generated
# This causes issues with filters that expect generated, not JSON data
# ex: "for (k, v) in gen" vs "for (k, v) in gen.items()" conflicts
def run_filter(j, cls, argsj={}, verbose=False):
    c = cls(argsj=argsj, verbose=verbose)
    ret = c.run(j)
    return jgen2j(ret)
