"""http-headers-scanner: which security headers one response carries.

One HEAD request; each missing header is a finding, and one INFO record
keeps the inventory of what was present. HSTS is only judged over HTTPS,
where browsers honour it.
"""

import http.client
import os

import samma_finding
from samma_finding import config

SCANNER = "http-headers-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

MISSING_CHECKS = {
    "content-security-policy": "SAMMA-HEADERS-CSP-MISSING",
    "x-content-type-options": "SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING",
    "x-frame-options": "SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING",
    "referrer-policy": "SAMMA-HEADERS-REFERRER-POLICY-MISSING",
    "permissions-policy": "SAMMA-HEADERS-PERMISSIONS-POLICY-MISSING",
}

VALUE_PREVIEW = 120


def settings(environ=None, cfg=None):
    """Environment > config.yaml > defaults. The port follows the scheme:
    HTTPS=True without PORT means 443, never the port config.yaml lists for
    plain HTTP (samma_finding.config.endpoint)."""
    env = os.environ if environ is None else environ
    section = config.section("http-headers-scanner", CONFIG_PATH, cfg)
    https, port = config.endpoint(env, section, default_https=False)
    return {
        "https": https,
        "port": port,
        "timeout": float(config.setting(env, section, "timeout", 5)),
    }


def fetch(target, opts):
    """``(status_code, {header: value})`` for ``HEAD /``; errors propagate."""
    if opts["https"]:
        conn = http.client.HTTPSConnection(target, opts["port"], timeout=opts["timeout"])
    else:
        conn = http.client.HTTPConnection(target, opts["port"], timeout=opts["timeout"])
    try:
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def _preview(value):
    value = " ".join(str(value).split())
    return value if len(value) <= VALUE_PREVIEW else value[:VALUE_PREVIEW] + "..."


def classify(headers, https, status_code=None):
    """``[(check_id, evidence, header)]``; ``header`` is ``None`` for the summary."""
    findings = []
    where = "response status %s" % status_code if status_code is not None else "response"
    if https and "strict-transport-security" not in headers:
        findings.append(("SAMMA-HEADERS-HSTS-MISSING",
                         "strict-transport-security not present (%s)" % where,
                         "strict-transport-security"))
    csp = headers.get("content-security-policy") or ""
    for header, check_id in MISSING_CHECKS.items():
        if header in headers:
            continue
        if header == "x-frame-options" and "frame-ancestors" in csp.lower():
            continue  # CSP frame-ancestors supersedes X-Frame-Options
        findings.append((check_id, "%s not present (%s)" % (header, where), header))
    xss = headers.get("x-xss-protection")
    if xss is not None and str(xss).strip().startswith("1"):
        findings.append(("SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED",
                         "x-xss-protection: %s" % _preview(xss), "x-xss-protection"))
    present = [h for h in SECURITY_HEADERS if h in headers]
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    summary = "%s; present: %s; missing: %s" % (
        where,
        ", ".join("%s=%s" % (h, _preview(headers[h])) for h in present) or "none",
        ", ".join(missing) or "none",
    )
    findings.append(("SAMMA-HEADERS-OBSERVED", summary, None))
    return findings


def scan(run, opts=None, fetch_=None):
    opts = opts or settings()
    status_code, headers = (fetch_ or fetch)(run.target, opts)
    scheme = "https" if opts["https"] else "http"
    endpoint = run.endpoint(port=opts["port"], scheme=scheme)
    base = {"host": run.target, "port": opts["port"], "https": opts["https"],
            "status_code": status_code, "type": "HTTPHeaders"}
    for check_id, evidence, header in classify(headers, opts["https"], status_code):
        raw = dict(base)
        if header is None:
            raw["headers"] = {h: headers.get(h) for h in SECURITY_HEADERS}
        else:
            raw.update({"header": header, "present": header in headers,
                        "value": headers.get(header)})
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
