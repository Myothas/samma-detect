"""Checks for waf-scanner, derived from passive fingerprints and the three
probe requests. Evidence names the indicators; header and cookie values stay
under ``raw`` and no response body is ever included."""

PREFIX = "SAMMA-WAF-"

CHECKS = {
    "SAMMA-WAF-DETECTED": {
        "severity": "INFO",
        "title": "Web application firewall or CDN detected",
        "remediation": "No action is needed. This record keeps the inventory of "
                       "which edge protection fronts the endpoint.",
        "references": [],
    },
    "SAMMA-WAF-NOT-DETECTED": {
        "severity": "LOW",
        "title": "No web application firewall detected",
        "remediation": "Consider fronting public web applications with a WAF or an "
                       "edge service that blocks common injection payloads. The "
                       "detection is heuristic: a WAF in monitor-only mode is not "
                       "seen.",
        "references": ["https://www.pcisecuritystandards.org/"],
    },
}
