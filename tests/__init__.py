"""Test package. Run from the repository root:

    python3 -m unittest discover -s tests -t .

The shared package lives in ``common/``; put it on the path once here.
"""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMON = os.path.join(REPO_ROOT, "common")
if COMMON not in sys.path:
    sys.path.insert(0, COMMON)
