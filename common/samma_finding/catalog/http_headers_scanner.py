"""Checks for http-headers-scanner, one per response header it inspects."""

PREFIX = "SAMMA-HEADERS-"

_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_CHEAT_SHEET = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
_MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"

CHECKS = {
    "SAMMA-HEADERS-HSTS-MISSING": {
        "severity": "MEDIUM",
        "title": "Strict-Transport-Security header is missing",
        "remediation": "Send Strict-Transport-Security: max-age=31536000; includeSubDomains "
                       "on every HTTPS response so browsers refuse plaintext connections.",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc6797",
            _CHEAT_SHEET,
        ],
    },
    "SAMMA-HEADERS-CSP-MISSING": {
        "severity": "LOW",
        "title": "Content-Security-Policy header is missing",
        "remediation": "Define a Content-Security-Policy that restricts script, style and "
                       "frame sources; start in report-only mode and tighten it.",
        "references": [_MDN + "Content-Security-Policy", _CHEAT_SHEET],
    },
    "SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING": {
        "severity": "LOW",
        "title": "X-Content-Type-Options header is missing",
        "remediation": "Send X-Content-Type-Options: nosniff so browsers do not guess "
                       "content types.",
        "references": [_MDN + "X-Content-Type-Options", _CHEAT_SHEET],
    },
    "SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING": {
        "severity": "LOW",
        "title": "X-Frame-Options header is missing",
        "remediation": "Send X-Frame-Options: DENY or SAMEORIGIN, or a "
                       "Content-Security-Policy with a frame-ancestors directive, to "
                       "prevent clickjacking.",
        "references": [_MDN + "X-Frame-Options", _CHEAT_SHEET],
    },
    "SAMMA-HEADERS-REFERRER-POLICY-MISSING": {
        "severity": "LOW",
        "title": "Referrer-Policy header is missing",
        "remediation": "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter) "
                       "so URLs are not leaked to other sites.",
        "references": [_MDN + "Referrer-Policy", _CHEAT_SHEET],
    },
    "SAMMA-HEADERS-PERMISSIONS-POLICY-MISSING": {
        "severity": "INFO",
        "title": "Permissions-Policy header is missing",
        "remediation": "Send a Permissions-Policy that disables browser features the "
                       "site does not use, such as camera, microphone and geolocation.",
        "references": [_MDN + "Permissions-Policy", _OWASP_HEADERS],
    },
    "SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED": {
        "severity": "INFO",
        "title": "Deprecated X-XSS-Protection header is enabled",
        "remediation": "The header is deprecated and its filter has caused vulnerabilities "
                       "in older browsers. Remove it or send X-XSS-Protection: 0 and rely "
                       "on Content-Security-Policy.",
        "references": [_MDN + "X-XSS-Protection", _OWASP_HEADERS],
    },
    "SAMMA-HEADERS-OBSERVED": {
        "severity": "INFO",
        "title": "HTTP security headers observed",
        "remediation": "No action is needed. This record keeps the inventory of which "
                       "security headers the endpoint sends.",
        "references": [_OWASP_HEADERS],
    },
}
