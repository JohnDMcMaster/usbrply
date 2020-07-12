from .fx2 import FX2Commenter


def run(filts, jgen, argsj={}):
    """
    Run series of given filters on input jgen
    First filter in array is applied first
    """
    if len(filts) == 0:
        return jgen

    filt0 = filts[0]
    cls = {
        "fx2": FX2Commenter,
    }[filt0]
    return run(filts[1:], cls(argsj).run(jgen), argsj=argsj)
