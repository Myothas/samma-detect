"""ssh-banner-scanner: the version string an SSH server sends first.

A port that refuses or times out means no SSH is exposed: the run succeeds
with no findings. A banner is classified for protocol 1 and old OpenSSH.
"""

import os
import re
import socket

import samma_finding
from samma_finding import config, netutil
from samma_finding.catalog import ssh_banner_scanner as checks

SCANNER = "ssh-banner-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

# SSH-<protoversion>-<softwareversion> [comment]   (RFC 4253 section 4.2)
BANNER_RE = re.compile(r"^SSH-(?P<protocol>[0-9.]+)-(?P<software>\S+)(?:\s+(?P<comment>.*))?$")
OPENSSH_RE = re.compile(r"OpenSSH_(\d+)\.(\d+)")
UNREACHABLE = (ConnectionRefusedError, ConnectionResetError, socket.timeout, TimeoutError)


def settings(environ=None, cfg=None):
    env = os.environ if environ is None else environ
    section = config.section("ssh-banner-scanner", CONFIG_PATH, cfg)
    return {
        "port": int(env.get("PORT", section.get("port", 22))),
        "timeout": float(env.get("TIMEOUT", section.get("timeout", 5))),
    }


def parse_banner(text):
    match = BANNER_RE.match(text or "")
    if not match:
        return {"protocol": None, "software": None, "comment": None}
    return match.groupdict()


def classify(banner):
    """``[(check_id, evidence)]`` for a banner line; empty when it is not SSH."""
    if not banner:
        return []
    parsed = parse_banner(banner)
    findings = []
    protocol = parsed.get("protocol") or ""
    if protocol.startswith("1."):
        findings.append(("SAMMA-SSH-PROTOCOL-V1",
                         "banner announces protocol %s: %s" % (protocol, banner)))
    match = OPENSSH_RE.search(parsed.get("software") or "")
    if match and int(match.group(1)) < checks.OPENSSH_MIN_MAJOR:
        findings.append(("SAMMA-SSH-VERSION-OUTDATED",
                         "OpenSSH %s.%s in banner: %s" % (match.group(1), match.group(2), banner)))
    findings.append(("SAMMA-SSH-BANNER", banner))
    return findings


def read_banner(target, opts, connect=netutil.connect_any):
    """``(banner, address)``; ``(None, None)`` when nothing listens."""
    try:
        sock, used = connect(target, opts["port"], opts["timeout"])
    except UNREACHABLE:
        return None, None
    with sock:
        data = sock.recv(256)
    return data.decode("utf-8", errors="replace").strip(), used.describe()


def scan(run, opts=None, connect=netutil.connect_any):
    opts = opts or settings()
    banner, address = read_banner(run.target, opts, connect)
    if not banner:
        return
    parsed = parse_banner(banner)
    raw = {"host": run.target, "port": opts["port"], "banner": banner,
           "software": parsed.get("software"), "type": "SSHBanner", "address": address}
    endpoint = run.endpoint(port=opts["port"], scheme="ssh")
    for check_id, evidence in classify(banner):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
