"""whois-scanner: registrar, dates and name servers for the target's domain.

The record is one inventory finding; a registration that has expired or is
about to is classified on top of it. A lookup error ends the run as failed.
"""

import os
from datetime import datetime, timezone

import samma_finding
from samma_finding.catalog import whois_scanner as checks

SCANNER = "whois-scanner"


def first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def as_datetime(value):
    value = first(value)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def as_text(value):
    value = first(value)
    return None if value is None else str(value)


def lookup_whois(target):
    """The registration record as a plain dict; errors propagate."""
    import whois  # third-party: python-whois, installed in the image
    w = whois.whois(target)
    name_servers = w.name_servers
    if isinstance(name_servers, (list, tuple)):
        servers = [str(n).lower() for n in name_servers if n]
    elif name_servers:
        servers = [str(name_servers).lower()]
    else:
        servers = []
    return {
        "registrar": as_text(w.registrar),
        "creation_date": as_text(w.creation_date),
        "expiration_date": as_text(w.expiration_date),
        "expiration": as_datetime(w.expiration_date),
        "name_servers": servers,
    }


def classify(record, now=None):
    """``[(check_id, evidence)]`` for a registration record."""
    now = now or datetime.now(timezone.utc)
    findings = []
    expiration = record.get("expiration")
    if expiration is not None:
        days = (expiration - now).days
        if days < 0:
            findings.append(("SAMMA-WHOIS-DOMAIN-EXPIRED",
                             "registration expired on %s (%d days ago)" % (expiration.date(), -days)))
        elif days <= checks.EXPIRY_WARNING_DAYS:
            findings.append(("SAMMA-WHOIS-DOMAIN-EXPIRING",
                             "registration expires on %s (%d days left)" % (expiration.date(), days)))
    findings.append(("SAMMA-WHOIS-RECORD", "registrar=%s created=%s expires=%s name_servers=%s" % (
        record.get("registrar"), record.get("creation_date"), record.get("expiration_date"),
        ", ".join(record.get("name_servers") or []) or "none")))
    return findings


def scan(run, lookup=lookup_whois):
    record = lookup(run.target)
    raw = {"host": run.target, "registrar": record.get("registrar"),
           "creation_date": record.get("creation_date"),
           "expiration_date": record.get("expiration_date"),
           "name_servers": record.get("name_servers") or [], "type": "WHOISScan"}
    endpoint = run.endpoint(scheme="whois")
    for check_id, evidence in classify(record):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
