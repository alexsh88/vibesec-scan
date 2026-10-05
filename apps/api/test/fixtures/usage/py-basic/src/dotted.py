# Dotted whole-module import -> symbol None; bound by its FULL dotted path. Attribute access is
# only reported once it walks past the imported path (see USAGES.md); an access that diverges
# before reaching the end of the path is not reported.
import yaml.loader

yaml.loader.Loader()
yaml.loader.other
yaml.different
yaml.other.Thing()
