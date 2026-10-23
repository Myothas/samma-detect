"""tls-scanner: one TLS handshake with the target and what it tells us.

The certificate, the negotiated protocol and cipher become findings; the
verification error, when there is one, is classified too. A connection that
cannot be made at all ends the run as failed.
"""

import os
import ssl
from datetime import datetime, timezone

import samma_finding
from samma_finding import config, netutil
from samma_finding.catalog import tls_scanner as checks

SCANNER = "tls-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

# OpenSSL reasons that mean the server only speaks TLS versions below the
# client's minimum (TLS 1.2), so the handshake fails instead of negotiating.
PROTOCOL_TOO_OLD_REASONS = ("UNSUPPORTED_PROTOCOL", "TLSV1_ALERT_PROTOCOL_VERSION")


def settings(environ=None, cfg=None):
    env = os.environ if environ is None else environ
    tls = config.section("tls-scanner", CONFIG_PATH, cfg)
    return {
        "port": int(env.get("PORT", tls.get("port", 443))),
        "timeout": float(env.get("TIMEOUT", tls.get("timeout", 5))),
        "verify_cert": config.truthy(env.get("VERIFY_CERT", tls.get("verify_cert", True))),
    }


def parse_certificate(cert, now=None):
    """Expiry and names from ``getpeercert()``'s dictionary."""
    now = now or datetime.now(timezone.utc)
    info = {"expires": None, "days_remaining": None, "expired": None,
            "subject_cn": None, "issuer": None}
    not_after_str = cert.get("notAfter")
    if not_after_str:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        not_after = not_after.replace(tzinfo=timezone.utc)
        info["days_remaining"] = (not_after - now).days
        info["expired"] = info["days_remaining"] < 0
        info["expires"] = not_after.strftime("%Y-%m-%d")
    for field in cert.get("subject", ()):
        for key, value in field:
            if key == "commonName":
                info["subject_cn"] = value
    for field in cert.get("issuer", ()):
        for key, value in field:
            if key == "organizationName":
                info["issuer"] = value
    return info


def is_weak_cipher(name):
    if not name:
        return False
    tokens = name.upper().replace("_", "-").split("-")
    return any(token in checks.WEAK_CIPHER_TOKENS for token in tokens)


def classify(observation):
    """``[(check_id, evidence)]`` for one handshake observation.

    ``observation`` has ``protocol``, ``cipher``, ``cert`` (the dict from
    :func:`parse_certificate` or ``None``), ``verify_error`` and
    ``protocol_error`` (strings or ``None``).
    """
    findings = []
    verify_error = observation.get("verify_error")
    if verify_error:
        if "expired" in verify_error.lower():
            findings.append(("SAMMA-TLS-CERT-EXPIRED",
                             "certificate verification failed: %s" % verify_error))
        else:
            findings.append(("SAMMA-TLS-CERT-INVALID",
                             "certificate verification failed: %s" % verify_error))
    protocol_error = observation.get("protocol_error")
    if protocol_error:
        findings.append(("SAMMA-TLS-PROTOCOL-DEPRECATED",
                         "handshake failed with %s: the server offers no TLS version "
                         "of 1.2 or newer" % protocol_error))
    protocol = observation.get("protocol")
    if protocol in checks.DEPRECATED_PROTOCOLS:
        findings.append(("SAMMA-TLS-PROTOCOL-DEPRECATED", "negotiated %s" % protocol))
    cipher = observation.get("cipher")
    if is_weak_cipher(cipher):
        findings.append(("SAMMA-TLS-CIPHER-WEAK", "negotiated cipher %s" % cipher))
    cert = observation.get("cert")
    if cert:
        days = cert.get("days_remaining")
        if cert.get("expired"):
            findings.append(("SAMMA-TLS-CERT-EXPIRED",
                             "certificate expired on %s (%d days ago)" % (cert["expires"], -days)))
        elif days is not None and days <= checks.EXPIRY_WARNING_DAYS:
            findings.append(("SAMMA-TLS-CERT-EXPIRING",
                             "certificate expires on %s (%d days left)" % (cert["expires"], days)))
    if protocol:
        summary = "protocol=%s cipher=%s" % (protocol, cipher)
        if cert:
            summary += " subject=%s issuer=%s expires=%s days_remaining=%s" % (
                cert.get("subject_cn"), cert.get("issuer"), cert.get("expires"),
                cert.get("days_remaining"))
        findings.append(("SAMMA-TLS-CERTIFICATE", summary))
    return findings


def handshake(target, opts, connect=netutil.connect_any):
    """Connect, shake hands and return ``(observation, raw)``."""
    if opts["verify_cert"]:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()
    sock, used = connect(target, opts["port"], opts["timeout"])  # OSError -> failed run
    observation = {"protocol": None, "cipher": None, "cert": None,
                   "verify_error": None, "protocol_error": None}
    raw = {
        "host": target, "port": opts["port"], "valid": False, "expired": None,
        "days_remaining": None, "expires": None, "subject_cn": None,
        "issuer": None, "protocol": None, "cipher": None, "type": "TLSScan",
        "address": used.describe(),
    }
    try:
        with sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = parse_certificate(ssock.getpeercert() or {})
                cipher_info = ssock.cipher()
                observation.update({
                    "protocol": ssock.version(),
                    "cipher": cipher_info[0] if cipher_info else None,
                    "cert": cert,
                })
    except ssl.SSLCertVerificationError as exc:
        observation["verify_error"] = getattr(exc, "verify_message", None) or str(exc)
        raw["error"] = observation["verify_error"]
    except ssl.SSLError as exc:
        reason = getattr(exc, "reason", None) or ""
        if reason not in PROTOCOL_TOO_OLD_REASONS:
            raise
        observation["protocol_error"] = reason
        raw["error"] = reason
    if observation["cert"]:
        raw.update(observation["cert"])
        raw["valid"] = True
    raw["protocol"] = observation["protocol"]
    raw["cipher"] = observation["cipher"]
    return observation, raw


def scan(run, opts=None, connect=netutil.connect_any):
    opts = opts or settings()
    observation, raw = handshake(run.target, opts, connect)
    endpoint = run.endpoint(port=opts["port"], scheme="https")
    for check_id, evidence in classify(observation):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
