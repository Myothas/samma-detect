"""Shared fixtures: load a scanner module from its directory, run it in memory."""

import importlib.util
import os
import sys

from samma_finding import Emitter, ListPublisher, Run

from . import REPO_ROOT

SCANNERS = (
    "dns-scanner", "http-headers-scanner", "http-redirect-scanner",
    "port-scanner", "ssh-banner-scanner", "tls-scanner",
    "traceroute-scanner", "waf-scanner", "whois-scanner",
)

_loaded = {}


def scan_py(scanner):
    return os.path.join(REPO_ROOT, scanner, "code", "scan.py")


def load_scanner(scanner):
    """Import ``<scanner>/code/scan.py`` as a module (no network, no main)."""
    if scanner in _loaded:
        return _loaded[scanner]
    name = "scanner_" + scanner.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, scan_py(scanner))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    _loaded[scanner] = module
    return module


def make_run(scanner, target="example.com"):
    """A ``Run`` whose messages land in the returned list publisher."""
    sink = ListPublisher()
    run = Run(scanner, target, Emitter([sink]), version="2.0.0-test", run="run-test")
    return run, sink


def execute(scanner, scan, target="example.com"):
    """Run ``scan`` under the outcome rules; return ``(exit_code, findings, run_message)``."""
    run, sink = make_run(scanner, target)
    code = run.execute(scan)
    findings = [m for m in sink.messages if m["kind"] == "finding"]
    runs = [m for m in sink.messages if m["kind"] == "run"]
    assert len(runs) == 1, "expected exactly one run message, got %d" % len(runs)
    return code, findings, runs[0]
