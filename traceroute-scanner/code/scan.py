"""traceroute-scanner: the network path to the target, hop by hop.

The whole path is one inventory finding. No hops at all (unknown host, a
missing binary) ends the run as failed.
"""

import os
import re
import subprocess

import samma_finding
from samma_finding import config

SCANNER = "traceroute-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

# "  1  1.2.3.4  12.345 ms" or "  1  *"
HOP_RE = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\d+\.\d+)\s+ms")
STAR_RE = re.compile(r"^\s*(\d+)\s+\*")


def settings(environ=None, cfg=None):
    env = os.environ if environ is None else environ
    section = config.section("traceroute-scanner", CONFIG_PATH, cfg)
    return {
        "max_hops": int(env.get("MAX_HOPS", section.get("max_hops", 30))),
        "timeout": int(env.get("TIMEOUT", section.get("timeout", 2))),
    }


def command(target, opts):
    return ["traceroute", "-n", "-q", "1", "-w", str(opts["timeout"]),
            "-m", str(opts["max_hops"]), target]


def parse(stdout):
    hops = []
    for line in stdout.splitlines():
        match = HOP_RE.match(line)
        if match:
            hops.append({"hop": int(match.group(1)), "ip": match.group(2),
                         "rtt_ms": float(match.group(3))})
            continue
        match = STAR_RE.match(line)
        if match:
            hops.append({"hop": int(match.group(1)), "ip": None, "rtt_ms": None})
    return hops


def summarize(hops):
    parts = []
    for h in hops:
        if h["ip"] is None:
            parts.append("%d *" % h["hop"])
        else:
            parts.append("%d %s %.1fms" % (h["hop"], h["ip"], h["rtt_ms"]))
    return "%d hop(s): %s" % (len(hops), "; ".join(parts))


def scan(run, opts=None, runner=subprocess.run):
    opts = opts or settings()
    result = runner(command(run.target, opts), capture_output=True, text=True)
    hops = parse(result.stdout or "")
    if not hops:
        detail = (result.stderr or "").strip().splitlines()
        raise RuntimeError("traceroute exited %s with no hops%s" % (
            result.returncode, ": " + detail[0][:120] if detail else ""))
    raw = {"host": run.target, "hops": hops, "type": "Traceroute",
           "reached": hops[-1]["ip"] is not None}
    run.finding("SAMMA-TRACEROUTE-PATH", run.endpoint(scheme="traceroute"),
                evidence=summarize(hops), raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
