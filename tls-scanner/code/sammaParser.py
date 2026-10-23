"""Compatibility shim: the v1 output API now lives in the shared package.

The scanner in this directory no longer imports it; it stays so out-of-tree
scanners built on the old two-file pattern keep working unchanged.
"""

from samma_finding.legacy import endThis, logger  # noqa: F401
