"""The check catalogues: the source of truth for check ids and severities.

One module per scanner. A check id is namespaced per scanner
(``SAMMA-TLS-...`` for ``tls-scanner``) and is never renamed: a renamed
check is a new check. Every id a scanner emits must exist here; the tests
in ``tests/test_catalog.py`` enforce that in both directions.

Run ``python3 -m samma_finding.catalog`` to print the catalogue as JSON.
"""

from .. import schema
from . import (dns_scanner, http_headers_scanner, http_redirect_scanner,
               port_scanner, ssh_banner_scanner, tls_scanner,
               traceroute_scanner, waf_scanner, whois_scanner)

SCANNERS = {
    "dns-scanner": dns_scanner,
    "http-headers-scanner": http_headers_scanner,
    "http-redirect-scanner": http_redirect_scanner,
    "port-scanner": port_scanner,
    "ssh-banner-scanner": ssh_banner_scanner,
    "tls-scanner": tls_scanner,
    "traceroute-scanner": traceroute_scanner,
    "waf-scanner": waf_scanner,
    "whois-scanner": whois_scanner,
}

REQUIRED_FIELDS = ("severity", "title", "remediation", "references")


class UnknownCheck(KeyError):
    """A scanner emitted a check id that is not in its catalogue."""


def for_scanner(scanner):
    try:
        module = SCANNERS[scanner]
    except KeyError:
        raise UnknownCheck("no catalogue for scanner %r" % (scanner,))
    return module.CHECKS


def prefix_for(scanner):
    return SCANNERS[scanner].PREFIX


def get(scanner, check_id):
    checks = for_scanner(scanner)
    try:
        return checks[check_id]
    except KeyError:
        raise UnknownCheck("%s is not in the %s catalogue" % (check_id, scanner))


def all_checks():
    """``{scanner: {check_id: entry}}`` for every scanner."""
    return {name: dict(module.CHECKS) for name, module in SCANNERS.items()}


def validate():
    """Return a list of problems; an empty list means the catalogue is sound."""
    problems = []
    for scanner, module in SCANNERS.items():
        prefix = getattr(module, "PREFIX", None)
        if not prefix or not prefix.startswith("SAMMA-") or not prefix.endswith("-"):
            problems.append("%s: PREFIX must look like SAMMA-NAME-" % scanner)
            continue
        for check_id, entry in module.CHECKS.items():
            where = "%s/%s" % (scanner, check_id)
            if not schema.CHECK_ID_PATTERN.match(check_id):
                problems.append("%s: id does not match %s" % (where, schema.CHECK_ID_PATTERN.pattern))
            if not check_id.startswith(prefix):
                problems.append("%s: id is not under the scanner prefix %s" % (where, prefix))
            for field in REQUIRED_FIELDS:
                if field not in entry:
                    problems.append("%s: missing %s" % (where, field))
            if entry.get("severity") not in schema.SEVERITIES:
                problems.append("%s: severity %r is not one of %s" % (where, entry.get("severity"), schema.SEVERITIES))
            if not str(entry.get("title", "")).strip():
                problems.append("%s: empty title" % where)
            if not str(entry.get("remediation", "")).strip():
                problems.append("%s: empty remediation" % where)
            if not isinstance(entry.get("references", []), (list, tuple)):
                problems.append("%s: references must be a list" % where)
            if not isinstance(entry.get("compliance", []), (list, tuple)):
                problems.append("%s: compliance must be a list" % where)
    return problems
