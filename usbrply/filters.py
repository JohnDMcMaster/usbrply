from .commenter import Commenter
from .setup_filter import SetupFilter


def run(filts, jgen, argsj={}, verbose=False):
    """
    Run series of given filters on input jgen
    First filter in array is applied first
    """
    if len(filts) == 0:
        return jgen

    filt0 = filts[0]
    cls = {
        "commenter": Commenter,
        "setup": SetupFilter,
    }[filt0]
    return run(filts[1:], cls(argsj).run(jgen), argsj=argsj, verbose=verbose)
