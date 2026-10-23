"""port-scanner: which TCP ports on the target accept a connection.

Every address the target resolves to (IPv4 and IPv6) is probed. A port that
accepts on any address is one finding, with the per-address detail under
``raw``; closed ports are not findings.
"""

import os

import samma_finding
from samma_finding import config, netutil
from samma_finding.catalog import port_scanner as checks

SCANNER = "port-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")
DEFAULT_PORTS = [80, 443, 8080, 8443]


def settings(environ=None, cfg=None):
    """PORT (single) > PORTS (comma-separated) > config defaults."""
    env = os.environ if environ is None else environ
    defaults = config.section("defaults", CONFIG_PATH, cfg)
    if env.get("PORT"):
        ports = [int(env["PORT"])]
    elif env.get("PORTS"):
        ports = [int(p.strip()) for p in env["PORTS"].split(",") if p.strip()]
    else:
        ports = [int(p) for p in defaults.get("ports", DEFAULT_PORTS)]
    timeout = float(env.get("TIMEOUT", defaults.get("timeout", 3)))
    return {"ports": ports, "timeout": timeout}


def classify(port):
    """The check an open ``port`` raises."""
    if port in checks.ADMIN_PORTS:
        return "SAMMA-PORT-OPEN-ADMIN"
    return "SAMMA-PORT-OPEN"


def scheme_for(port):
    return checks.SCHEMES.get(port) or checks.ADMIN_PORTS.get(port) or "tcp"


def scan(run, opts=None, resolve=netutil.resolve, probe=netutil.probe_port):
    opts = opts or settings()
    addresses = resolve(run.target)  # socket.gaierror ends the run as failed
    for port in opts["ports"]:
        results = []
        for address in addresses:
            is_open = probe(address, port, opts["timeout"])
            entry = address.describe()
            entry["status"] = "open" if is_open else "closed"
            results.append(entry)
        open_on = [r for r in results if r["status"] == "open"]
        if not open_on:
            continue
        evidence = "tcp/%d open on %s" % (
            port, ", ".join("%s (%s)" % (r["address"], r["family"]) for r in open_on))
        service = checks.ADMIN_PORTS.get(port)
        if service:
            evidence += "; port is normally %s" % service
        raw = {
            "host": run.target,
            "port": port,
            "status": "open",
            "type": "PortScan",
            "addresses": results,
        }
        run.finding(classify(port), run.endpoint(port=port, scheme=scheme_for(port)),
                    evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
