"""Message schema v2 for the samma detect scanners.

Two message kinds travel on NATS and into the ``/out/<scanner>.json`` file:

* ``finding``: one failing check on one endpoint (or one INFO inventory fact).
* ``run``: sent exactly once when the scan ends, with the outcome.

Both carry the common envelope built by :func:`envelope`. The legacy
``samma-io`` block is kept unchanged so existing consumers keep working, and
the scanner's own record is kept under ``raw`` (with ``host``, ``port``,
``status`` and ``type`` mirrored at the top level for the current bridge).
"""

import json
import os
import re
import socket
from datetime import datetime, timezone

SCHEMA_V2 = "samma.io/scan/v2"

KIND_FINDING = "finding"
KIND_RUN = "run"
KINDS = (KIND_FINDING, KIND_RUN)

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"
SEVERITIES = (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOME_TIMED_OUT = "timed_out"
OUTCOMES = (OUTCOME_SUCCEEDED, OUTCOME_FAILED, OUTCOME_TIMED_OUT)

# Evidence is a short summary, never a response body.
EVIDENCE_MAX_BYTES = 1024
# A run message's free-text reason is kept short as well.
MESSAGE_MAX_BYTES = 512

CHECK_ID_PATTERN = re.compile(r"^SAMMA-[A-Z0-9]+(?:-[A-Z0-9]+)+$")
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Keys of the scanner record that the current bridge reads from the top
# level of every message (operator/bridge/code/bridge.py). They are mirrored
# there so its table columns keep filling; new consumers read ``raw``.
LEGACY_TOP_LEVEL_KEYS = ("host", "port", "status", "type")

DEFAULT_VERSION_FILES = ("/VERSION",)


class SchemaError(ValueError):
    """A message would not satisfy schema v2."""


def utc_now():
    return datetime.now(timezone.utc)


def rfc3339(moment):
    """Format an aware datetime as RFC 3339 UTC with second precision."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cap_text(text, limit):
    """Return ``text`` cut to at most ``limit`` UTF-8 bytes.

    Whitespace runs are folded into single spaces first, because the field
    is a one-line summary. A cut string ends in ``...`` and still fits.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = " ".join(text.split())
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    marker = b"..."
    head = encoded[: max(limit - len(marker), 0)]
    return head.decode("utf-8", "ignore") + marker.decode("ascii")


def cap_evidence(text):
    return cap_text(text, EVIDENCE_MAX_BYTES)


def scanner_version(version_files=DEFAULT_VERSION_FILES):
    """The scanner family version: ``SAMMA_SCANNER_VERSION`` or a VERSION file.

    The Dockerfiles copy the repository's ``VERSION`` to ``/VERSION``; when
    the scanners run from a checkout the file next to ``common/`` is used.
    """
    env = os.getenv("SAMMA_SCANNER_VERSION", "").strip()
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(here))
    candidates = list(version_files) + [os.path.join(repo_root, "VERSION")]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                value = handle.read().strip()
        except OSError:
            continue
        if value:
            return value
    return "unknown"


def run_id():
    """``SAMMA_RUN_ID`` or the hostname, which is the Job's pod name."""
    env = os.getenv("SAMMA_RUN_ID", "").strip()
    if env:
        return env
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def legacy_block(scanner):
    """The ``samma-io`` block exactly as the v1 parser built it."""
    tags_raw = os.getenv("SAMMA_IO_TAGS", "scanner")
    return {
        "scanner": os.getenv("SAMMA_IO_SCANNER", scanner),
        "id": os.getenv("SAMMA_IO_ID", "1234"),
        "tags": [t.strip() for t in tags_raw.split(",") if t.strip()],
        "json": os.getenv("SAMMA_IO_JSON", "{}"),
    }


def envelope(kind, scanner, target, run, version, emitted_at=None):
    if kind not in KINDS:
        raise SchemaError("unknown message kind: %r" % (kind,))
    return {
        "schema": SCHEMA_V2,
        "kind": kind,
        "scanner": scanner,
        "scannerVersion": version,
        "target": target,
        "runId": run,
        "emittedAt": rfc3339(emitted_at or utc_now()),
        "samma-io": legacy_block(scanner),
    }


def endpoint(host, port=None, scheme=None):
    if port is not None:
        port = int(port)
        if not 0 < port < 65536:
            raise SchemaError("endpoint port out of range: %r" % (port,))
    return {"host": host, "port": port, "scheme": scheme}


def _json_safe(value):
    """Return ``value`` reduced to JSON types (datetimes become strings)."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, datetime):
        return rfc3339(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def build_finding(scanner, target, run, version, check, check_id, endpoint_,
                  evidence="", raw=None, cve_ids=(), emitted_at=None):
    """Assemble one finding message from a catalogue entry ``check``."""
    if not CHECK_ID_PATTERN.match(check_id):
        raise SchemaError("check id %r is not of the form SAMMA-<SCANNER>-<NAME>" % (check_id,))
    severity = check["severity"]
    if severity not in SEVERITIES:
        raise SchemaError("check %s has unknown severity %r" % (check_id, severity))
    cves = []
    for cve in cve_ids:
        cve = str(cve).upper()
        if not CVE_ID_PATTERN.match(cve):
            raise SchemaError("not a CVE id: %r" % (cve,))
        cves.append(cve)
    raw = _json_safe(dict(raw or {}))
    message = envelope(KIND_FINDING, scanner, target, run, version, emitted_at)
    message.update({
        "checkId": check_id,
        "severity": severity,
        "title": check["title"],
        "endpoint": endpoint_,
        "evidence": cap_evidence(evidence),
        "remediation": check.get("remediation", ""),
        "references": list(check.get("references", ())),
        "cveIds": cves,
        "compliance": list(check.get("compliance", ())),
        "raw": raw,
    })
    for key in LEGACY_TOP_LEVEL_KEYS:
        if key in raw:
            message[key] = raw[key]
    return message


def build_run(scanner, target, run, version, outcome, message, started_at,
              finished_at, finding_count, emitted_at=None):
    """Assemble the single run message that ends every scan."""
    if outcome not in OUTCOMES:
        raise SchemaError("unknown run outcome: %r" % (outcome,))
    body = envelope(KIND_RUN, scanner, target, run, version, emitted_at or finished_at)
    body.update({
        "outcome": outcome,
        "message": cap_text(message, MESSAGE_MAX_BYTES),
        "startedAt": rfc3339(started_at),
        "finishedAt": rfc3339(finished_at),
        "findingCount": int(finding_count),
        # The v1 end marker, kept for consumers that key on it.
        "scan": "done",
    })
    return body


def dumps(message):
    """Serialise a message the way every output path does."""
    return json.dumps(message, ensure_ascii=False, sort_keys=True,
                      separators=(",", ": "))
