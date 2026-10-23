"""Checks for ssh-banner-scanner, derived from the version string the
server sends before key exchange."""

PREFIX = "SAMMA-SSH-"

# OpenSSH releases below this major version are out of upstream support.
OPENSSH_MIN_MAJOR = 8

CHECKS = {
    "SAMMA-SSH-PROTOCOL-V1": {
        "severity": "HIGH",
        "title": "SSH protocol version 1 is offered",
        "remediation": "Disable SSH protocol 1 (Protocol 2 in sshd_config, or upgrade "
                       "to a server that only speaks protocol 2).",
        "references": ["https://datatracker.ietf.org/doc/html/rfc4253"],
    },
    "SAMMA-SSH-VERSION-OUTDATED": {
        "severity": "MEDIUM",
        "title": "Outdated OpenSSH version in banner",
        "remediation": "Upgrade OpenSSH to a supported release (8.x or newer) or "
                       "restrict SSH to trusted networks.",
        "references": ["https://www.openssh.com/releasenotes.html"],
    },
    "SAMMA-SSH-BANNER": {
        "severity": "INFO",
        "title": "SSH service banner observed",
        "remediation": "No action is needed. This record keeps the SSH inventory; "
                       "consider whether SSH needs to be reachable from the internet.",
        "references": ["https://datatracker.ietf.org/doc/html/rfc4253"],
    },
}
