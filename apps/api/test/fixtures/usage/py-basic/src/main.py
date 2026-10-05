# Plain whole-module import -> symbol None; member/call tracked via attribute access.
import yaml
# Aliased whole-module import -> symbol None; tracked under the alias.
import yaml as y
# Named imports, with and without aliasing -> symbol is the ORIGINAL name, never the local alias.
from yaml import load, safe_load as sl
# `from a.b import c` -> package matched via the dotted module prefix.
from yaml.loader import Loader
# Relative imports -> always ignored (local modules).
from . import local_sibling
from .pkg import other_local
# Star import -> ignored (can't resolve statically what landed in scope).
from yaml import *
# Unrelated stdlib import -> no match, no usage.
import os

yaml.load(1)
yaml.FullLoader
y.safe_load(1)
y.other
load(1)
sl(1)
Loader

# Same line, two calls of the same binding -> dedupes to one usage record.
def twice():
    load(1); load(2)
