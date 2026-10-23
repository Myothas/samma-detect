"""Checks for traceroute-scanner: one inventory record per target."""

PREFIX = "SAMMA-TRACEROUTE-"

CHECKS = {
    "SAMMA-TRACEROUTE-PATH": {
        "severity": "INFO",
        "title": "Network path observed",
        "remediation": "No action is needed. This record keeps the hop-by-hop path "
                       "so routing changes can be seen.",
        "references": [],
    },
}
