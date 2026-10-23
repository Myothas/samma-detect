"""Checks for tls-scanner. The scanner makes one handshake with a default
client, so a protocol or cipher finding describes what was negotiated."""

PREFIX = "SAMMA-TLS-"

DEPRECATED_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
# Tokens of an OpenSSL cipher name that mark it as weak.
WEAK_CIPHER_TOKENS = ("RC4", "RC2", "DES", "3DES", "NULL", "EXP", "EXPORT", "MD5",
                      "ADH", "AECDH", "ANON")
EXPIRY_WARNING_DAYS = 14

_TLS_CHEAT_SHEET = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"

CHECKS = {
    "SAMMA-TLS-PROTOCOL-DEPRECATED": {
        "severity": "HIGH",
        "title": "Deprecated TLS protocol version negotiated",
        "remediation": "Disable SSLv3, TLS 1.0 and TLS 1.1 in the ingress controller or "
                       "server TLS options and allow TLS 1.2 and 1.3 only.",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc8996",
            _TLS_CHEAT_SHEET,
        ],
    },
    "SAMMA-TLS-CIPHER-WEAK": {
        "severity": "MEDIUM",
        "title": "Weak cipher suite negotiated",
        "remediation": "Remove RC4, DES, 3DES, NULL, export and anonymous cipher suites "
                       "and suites with MD5 from the server cipher list; prefer "
                       "AEAD suites with forward secrecy.",
        "references": [
            "https://datatracker.ietf.org/doc/html/rfc7465",
            _TLS_CHEAT_SHEET,
        ],
    },
    "SAMMA-TLS-CERT-EXPIRED": {
        "severity": "HIGH",
        "title": "TLS certificate has expired",
        "remediation": "Renew the certificate and reload the server or ingress. "
                       "Automate renewal (for example with cert-manager) so this "
                       "does not recur.",
        "references": [_TLS_CHEAT_SHEET],
    },
    "SAMMA-TLS-CERT-EXPIRING": {
        "severity": "MEDIUM",
        "title": "TLS certificate expires within 14 days",
        "remediation": "Renew the certificate before it expires and check that "
                       "automated renewal is working.",
        "references": [_TLS_CHEAT_SHEET],
    },
    "SAMMA-TLS-CERT-INVALID": {
        "severity": "HIGH",
        "title": "TLS certificate failed verification",
        "remediation": "Serve a certificate issued by a trusted CA whose subject or "
                       "subject alternative names match the hostname, with the full "
                       "intermediate chain.",
        "references": [_TLS_CHEAT_SHEET],
    },
    "SAMMA-TLS-CERTIFICATE": {
        "severity": "INFO",
        "title": "TLS certificate observed",
        "remediation": "No action is needed. This record keeps the certificate "
                       "inventory: issuer, expiry, negotiated protocol and cipher.",
        "references": [],
    },
}
