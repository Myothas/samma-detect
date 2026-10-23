"""dns-scanner: the A, AAAA, MX and TXT records of the target.

One inventory record per target carries every answer; a name that does not
exist is its own finding. When every query errors the run is failed.
"""

import os

import samma_finding
from samma_finding import config
from samma_finding.run import describe_exception

SCANNER = "dns-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "TXT"]


class NameDoesNotExist(Exception):
    """The resolver answered NXDOMAIN."""


def settings(environ=None, cfg=None):
    env = os.environ if environ is None else environ
    section = config.section("dns-scanner", CONFIG_PATH, cfg)
    raw = env.get("RECORD_TYPES", "")
    if raw:
        types = [r.strip().upper() for r in raw.split(",") if r.strip()]
    else:
        types = [str(r).upper() for r in section.get("record_types", DEFAULT_RECORD_TYPES)]
    return {"record_types": types}


def query_dns(target, rtype):
    """``[value, ...]`` or ``None`` for no answer; raises ``NameDoesNotExist``."""
    import dns.resolver  # third-party: dnspython, installed in the image
    try:
        return [rdata.to_text() for rdata in dns.resolver.resolve(target, rtype)]
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        raise NameDoesNotExist(target)


def collect(target, record_types, query=query_dns):
    """``(records, errors, nxdomain)`` over every record type."""
    records = []
    errors = []
    for rtype in record_types:
        try:
            values = query(target, rtype)
        except NameDoesNotExist:
            return records, errors, True
        except Exception as exc:
            errors.append({"record_type": rtype, "error": describe_exception(exc)})
            continue
        if values is None:
            records.append({"record_type": rtype, "value": None})
        else:
            for value in values:
                records.append({"record_type": rtype, "value": value})
    return records, errors, False


def summarize(records, errors):
    by_type = {}
    for r in records:
        by_type.setdefault(r["record_type"], [])
        if r["value"] is not None:
            by_type[r["record_type"]].append(r["value"])
    parts = ["%s: %s" % (rtype, ", ".join(values) if values else "none")
             for rtype, values in by_type.items()]
    parts.extend("%s: error %s" % (e["record_type"], e["error"]) for e in errors)
    return "; ".join(parts)


def scan(run, opts=None, query=query_dns):
    opts = opts or settings()
    records, errors, nxdomain = collect(run.target, opts["record_types"], query)
    endpoint = run.endpoint(scheme="dns")
    if nxdomain:
        run.finding("SAMMA-DNS-NXDOMAIN", endpoint, evidence="NXDOMAIN for %s" % run.target,
                    raw={"host": run.target, "error": "NXDOMAIN", "type": "DNSScan"})
        return
    if errors and len(errors) == len(opts["record_types"]):
        raise LookupError("every DNS query failed: " + "; ".join(
            "%s %s" % (e["record_type"], e["error"]) for e in errors))
    raw = {"host": run.target, "records": records, "errors": errors, "type": "DNSScan"}
    run.finding("SAMMA-DNS-RECORDS", endpoint, evidence=summarize(records, errors), raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
