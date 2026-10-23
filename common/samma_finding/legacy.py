"""The v1 ``sammaParser`` API, kept for scanners outside this repository.

``logger(record)`` emits the record with the ``samma-io`` block added, as
before, and ``endThis()`` writes ``{"scan": "done"}`` and ``/out/die``. The
scanners in this repository no longer call these; they go through
``samma_finding.main`` and emit schema v2 messages instead.
"""

import os

from . import schema
from .output import Emitter
from .run import write_die_file

_emitter = None


def _get_emitter():
    global _emitter
    if _emitter is None:
        scanner = os.getenv("SAMMA_IO_SCANNER", os.getenv("PARSER", "scanner"))
        _emitter = Emitter.from_env(scanner)
    return _emitter


def logger(json_data):
    """Add the ``samma-io`` block and send the record everywhere (v1 shape)."""
    scanner = os.getenv("SAMMA_IO_SCANNER", os.getenv("PARSER", "scanner"))
    json_data["samma-io"] = schema.legacy_block(scanner)
    _get_emitter().emit(json_data)


def endThis():
    """Log the v1 end marker, close the publishers and write ``/out/die``."""
    logger({"scan": "done"})
    emitter = _get_emitter()
    emitter.close()
    write_die_file()
