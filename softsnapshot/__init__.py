import sys
assert sys.version_info[:2] in [(3, 6), (3, 7)], "Unsupported Python Version"

from .core import SoftSnapshot
