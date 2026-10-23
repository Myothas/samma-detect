"""Checks for http-redirect-scanner, derived from the hop-by-hop chain."""

PREFIX = "SAMMA-REDIRECT-"

_MDN_REDIRECTS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"
_HSTS_RFC = "https://datatracker.ietf.org/doc/html/rfc6797"

CHECKS = {
    "SAMMA-REDIRECT-HTTPS-MISSING": {
        "severity": "MEDIUM",
        "title": "HTTP is not redirected to HTTPS",
        "remediation": "Redirect every plaintext HTTP request to the HTTPS URL with a "
                       "301 or 308, and send Strict-Transport-Security on the HTTPS "
                       "response.",
        "references": [_HSTS_RFC, _MDN_REDIRECTS],
    },
    "SAMMA-REDIRECT-DOWNGRADE": {
        "severity": "MEDIUM",
        "title": "Redirect chain downgrades HTTPS to HTTP",
        "remediation": "Make every hop of the redirect chain use HTTPS; a downgrade "
                       "exposes the request to interception.",
        "references": [_HSTS_RFC, _MDN_REDIRECTS],
    },
    "SAMMA-REDIRECT-OFFSITE": {
        "severity": "INFO",
        "title": "Redirect leaves the target host",
        "remediation": "Confirm the destination host is yours and intended; an "
                       "unexpected destination can mean a stale rule or a hijacked "
                       "record.",
        "references": [_MDN_REDIRECTS],
    },
    "SAMMA-REDIRECT-TOO-MANY": {
        "severity": "LOW",
        "title": "Redirect chain exceeded the hop limit",
        "remediation": "Fix the redirect rules so a request settles within a few hops; "
                       "a loop makes the site unreachable.",
        "references": [_MDN_REDIRECTS],
    },
    "SAMMA-REDIRECT-BROKEN": {
        "severity": "LOW",
        "title": "Redirect target could not be reached",
        "remediation": "Point the redirect at a URL that answers; check DNS and TLS "
                       "on the destination host.",
        "references": [_MDN_REDIRECTS],
    },
    "SAMMA-REDIRECT-CHAIN": {
        "severity": "INFO",
        "title": "HTTP redirect chain observed",
        "remediation": "No action is needed. This record keeps the redirect chain "
                       "inventory, hop by hop.",
        "references": [_MDN_REDIRECTS],
    },
}
