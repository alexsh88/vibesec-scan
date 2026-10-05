# Documented limitation: no scope analysis. A nested function parameter named `load` shadows the
# import of the same name, but the analyzer still (incorrectly) reports the call below as a usage.
from yaml import load


def unrelated(load):
    return load(1)
