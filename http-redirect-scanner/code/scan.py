"""http-redirect-scanner: the redirect chain from the target, hop by hop.

The chain is classified once it settles: plain HTTP that never reaches
HTTPS, an HTTPS to HTTP downgrade, a hop that leaves the host, a chain
that does not terminate, and the chain itself as an inventory record.
"""

import ipaddress
import os
import urllib.error
import urllib.parse
import urllib.request

import samma_finding
from samma_finding import config
from samma_finding.run import describe_exception

SCANNER = "http-redirect-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")
REDIRECT_CODES = (301, 302, 303, 307, 308)
DEFAULT_PORTS = {"http": 80, "https": 443}


def settings(environ=None, cfg=None):
    """Environment > config.yaml > defaults. The chain starts over plain
    HTTP on port 80 unless HTTPS (and PORT) say otherwise; the port follows
    the scheme (samma_finding.config.endpoint). A TARGET given as a URL
    keeps its own scheme and port."""
    env = os.environ if environ is None else environ
    section = config.section("http-redirect-scanner", CONFIG_PATH, cfg)
    https, port = config.endpoint(env, section, default_https=False)
    return {
        "https": https,
        "port": port,
        "timeout": float(config.setting(env, section, "timeout", 5)),
        "max_redirects": int(config.setting(env, section, "max_redirects", 10)),
    }


def to_url(target, opts=None):
    """The URL the chain starts from.

    A target that is already a URL is used as is. A bare host or IP gets the
    scheme and port from ``opts`` (plain HTTP on 80 when there are none);
    the port is written only when it is not the scheme's own, and IPv6
    literals get brackets.
    """
    if target.startswith("http://") or target.startswith("https://"):
        return target
    opts = opts or {}
    scheme = "https" if opts.get("https") else "http"
    host = target
    try:
        if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address):
            host = "[%s]" % target
    except ValueError:
        pass
    url = "%s://%s" % (scheme, host)
    port = opts.get("port")
    if port and int(port) != DEFAULT_PORTS[scheme]:
        url = "%s:%d" % (url, int(port))
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def default_opener():
    return urllib.request.build_opener(_NoRedirect())


def follow(start_url, opts, opener=None):
    """``(hops, stop, error)``: ``stop`` is ``final``, ``too_many`` or ``error``."""
    opener = opener or default_opener()
    hops = []
    current = start_url
    hop = 0
    while hop < opts["max_redirects"]:
        try:
            resp = opener.open(current, timeout=opts["timeout"])
            hops.append({"hop": hop, "url": current, "status_code": resp.status,
                         "redirect_to": None, "final": True})
            return hops, "final", None
        except urllib.error.HTTPError as exc:
            if exc.code in REDIRECT_CODES:
                location = urllib.parse.urljoin(current, exc.headers.get("Location", ""))
                hops.append({"hop": hop, "url": current, "status_code": exc.code,
                             "redirect_to": location, "final": False})
                current = location
                hop += 1
                continue
            hops.append({"hop": hop, "url": current, "status_code": exc.code,
                         "redirect_to": None, "final": True})
            return hops, "final", None
        except Exception as exc:
            hops.append({"hop": hop, "url": current, "error": describe_exception(exc),
                         "final": True})
            return hops, "error", exc
    return hops, "too_many", None


def _site(url):
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def chain_text(hops):
    parts = []
    for h in hops:
        if "error" in h:
            parts.append("%s [%s]" % (h["url"], h["error"]))
        else:
            parts.append("%s [%s]" % (h["url"], h["status_code"]))
    return " -> ".join(parts)


def classify(start_url, hops, stop):
    """``[(check_id, evidence)]`` for a settled chain."""
    findings = []
    chain = chain_text(hops)
    start_scheme = urllib.parse.urlsplit(start_url).scheme
    final = hops[-1] if hops and hops[-1].get("final") and "error" not in hops[-1] else None
    if start_scheme == "http" and final and urllib.parse.urlsplit(final["url"]).scheme == "http":
        findings.append(("SAMMA-REDIRECT-HTTPS-MISSING",
                         "final URL %s is plain http; chain: %s" % (final["url"], chain)))
    previous_scheme = start_scheme
    for h in hops[1:]:
        scheme = urllib.parse.urlsplit(h["url"]).scheme
        if previous_scheme == "https" and scheme == "http":
            findings.append(("SAMMA-REDIRECT-DOWNGRADE",
                             "hop %d goes from https to %s; chain: %s" % (h["hop"], h["url"], chain)))
            break
        previous_scheme = scheme
    start_site = _site(start_url)
    for h in hops[1:]:
        if _site(h["url"]) != start_site:
            findings.append(("SAMMA-REDIRECT-OFFSITE",
                             "hop %d leaves %s for %s" % (h["hop"], start_site, _site(h["url"]))))
            break
    if stop == "too_many":
        findings.append(("SAMMA-REDIRECT-TOO-MANY",
                         "%d hops without a final response; chain: %s" % (len(hops), chain)))
    if stop == "error" and hops and hops[-1]["hop"] > 0:
        findings.append(("SAMMA-REDIRECT-BROKEN",
                         "hop %d %s failed: %s" % (hops[-1]["hop"], hops[-1]["url"], hops[-1]["error"])))
    findings.append(("SAMMA-REDIRECT-CHAIN", "%d hop(s): %s" % (len(hops), chain)))
    return findings


def scan(run, opts=None, opener=None):
    opts = opts or settings()
    start_url = to_url(run.target, opts)
    hops, stop, error = follow(start_url, opts, opener)
    if stop == "error" and hops and hops[-1]["hop"] == 0:
        raise error  # the start URL itself could not be fetched: failed run
    parts = urllib.parse.urlsplit(start_url)
    endpoint = run.endpoint(host=parts.hostname, port=parts.port or DEFAULT_PORTS.get(parts.scheme),
                            scheme=parts.scheme)
    raw = {"host": run.target, "url": start_url, "hops": hops, "stop": stop,
           "type": "HTTPRedirect"}
    for check_id, evidence in classify(start_url, hops, stop):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
