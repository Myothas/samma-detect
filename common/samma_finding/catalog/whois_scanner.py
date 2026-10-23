"""Checks for whois-scanner, derived from the registration record."""

PREFIX = "SAMMA-WHOIS-"

EXPIRY_WARNING_DAYS = 30

CHECKS = {
    "SAMMA-WHOIS-RECORD": {
        "severity": "INFO",
        "title": "WHOIS record observed",
        "remediation": "No action is needed. This record keeps registrar, creation "
                       "and expiry dates and name servers so ownership changes "
                       "can be tracked.",
        "references": [],
    },
    "SAMMA-WHOIS-DOMAIN-EXPIRING": {
        "severity": "MEDIUM",
        "title": "Domain registration expires within 30 days",
        "remediation": "Renew the domain with the registrar and turn on auto-renewal. "
                       "An expired domain can be registered by someone else.",
        "references": [],
    },
    "SAMMA-WHOIS-DOMAIN-EXPIRED": {
        "severity": "HIGH",
        "title": "Domain registration has expired",
        "remediation": "Renew the domain immediately; after the grace period it can "
                       "be registered by someone else and every host under it "
                       "taken over.",
        "references": [],
    },
}
