"""samma_finding: schema v2 findings and run outcomes for the detect scanners.

A scanner is a function that takes a :class:`Run` and emits findings::

    import samma_finding

    def scan(run):
        run.finding("SAMMA-PORT-OPEN", run.endpoint(port=443, scheme="https"),
                    evidence="tcp/443 open", raw={"host": run.target, "port": 443})

    if __name__ == "__main__":
        samma_finding.main("port-scanner", scan)

``main`` reads ``TARGET`` and the output environment (``WRITE_TO_FILE``,
``NATS_ENABLED`` and friends), runs ``scan`` and ends the run with exactly
one run message carrying the outcome.
"""

from . import catalog, config, netutil, schema
from .output import Emitter, ListPublisher
from .run import Run, ScanTimedOut, main

__all__ = [
    "Emitter", "ListPublisher", "Run", "ScanTimedOut", "catalog", "config",
    "main", "netutil", "schema",
]
