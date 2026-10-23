"""Checks for dns-scanner: one inventory record per target, one check for a
name that does not exist."""

PREFIX = "SAMMA-DNS-"

CHECKS = {
    "SAMMA-DNS-RECORDS": {
        "severity": "INFO",
        "title": "DNS records observed",
        "remediation": "No action is needed. This record keeps the DNS inventory so "
                       "changes and dangling records can be tracked.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc1035"],
    },
    "SAMMA-DNS-NXDOMAIN": {
        "severity": "LOW",
        "title": "DNS name does not exist",
        "remediation": "Create the DNS record for the host or remove the Ingress or "
                       "scanner target that references it.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc1035"],
    },
}
