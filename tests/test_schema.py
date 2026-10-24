import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from samma_finding import catalog, schema
from .helpers import make_run

RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

FINDING_KEYS = {
    "schema", "kind", "scanner", "scannerVersion", "target", "runId", "emittedAt",
    "samma-io", "checkId", "severity", "title", "endpoint", "evidence",
    "remediation", "references", "cveIds", "compliance", "raw",
}
RUN_KEYS = {
    "schema", "kind", "scanner", "scannerVersion", "target", "runId", "emittedAt",
    "samma-io", "outcome", "message", "startedAt", "finishedAt", "findingCount", "scan",
}


class FindingShapeTest(unittest.TestCase):
    def test_finding_message_shape(self):
        run, sink = make_run("port-scanner")
        raw = {"host": "example.com", "port": 443, "status": "open", "type": "PortScan"}
        msg = run.finding("SAMMA-PORT-OPEN", run.endpoint(port=443, scheme="https"),
                          evidence="tcp/443 open", raw=raw)
        self.assertEqual(set(msg) - set(schema.LEGACY_TOP_LEVEL_KEYS), FINDING_KEYS)
        self.assertEqual(msg["schema"], "samma.io/scan/v2")
        self.assertEqual(msg["kind"], "finding")
        self.assertEqual(msg["scanner"], "port-scanner")
        self.assertEqual(msg["scannerVersion"], "2.0.0-test")
        self.assertEqual(msg["runId"], "run-test")
        self.assertEqual(msg["target"], "example.com")
        self.assertEqual(msg["severity"], "INFO")
        self.assertEqual(msg["title"], catalog.get("port-scanner", "SAMMA-PORT-OPEN")["title"])
        self.assertEqual(msg["endpoint"], {"host": "example.com", "port": 443, "scheme": "https"})
        self.assertEqual(msg["cveIds"], [])
        self.assertEqual(msg["compliance"], [])
        self.assertEqual(msg["raw"], raw)
        self.assertTrue(RFC3339.match(msg["emittedAt"]))
        self.assertIs(sink.messages[0], msg)

    def test_legacy_block_and_top_level_mirror_for_the_current_bridge(self):
        env = {"SAMMA_IO_SCANNER": "custom", "SAMMA_IO_ID": "77",
               "SAMMA_IO_TAGS": "a, b,,", "SAMMA_IO_JSON": '{"x":1}'}
        with mock.patch.dict(os.environ, env, clear=False):
            run, _ = make_run("tls-scanner")
            msg = run.finding("SAMMA-TLS-CERTIFICATE", run.endpoint(port=443, scheme="https"),
                              raw={"host": "example.com", "port": 443, "type": "TLSScan"})
        self.assertEqual(msg["samma-io"], {"scanner": "custom", "id": "77",
                                           "tags": ["a", "b"], "json": '{"x":1}'})
        self.assertEqual(msg["host"], "example.com")
        self.assertEqual(msg["port"], 443)
        self.assertEqual(msg["type"], "TLSScan")
        self.assertNotIn("status", msg)

    def test_evidence_capped_at_1_kib_on_a_utf8_boundary(self):
        run, _ = make_run("dns-scanner")
        long_text = "é" * 3000  # two bytes each
        msg = run.finding("SAMMA-DNS-RECORDS", run.endpoint(scheme="dns"), evidence=long_text)
        encoded = msg["evidence"].encode("utf-8")
        self.assertLessEqual(len(encoded), schema.EVIDENCE_MAX_BYTES)
        self.assertTrue(msg["evidence"].endswith("..."))
        msg["evidence"].encode("utf-8")  # a clean string, no half characters

    def test_evidence_is_folded_to_one_line(self):
        self.assertEqual(schema.cap_evidence("a\n\n  b\t c "), "a b c")
        self.assertEqual(schema.cap_evidence(None), "")

    def test_unknown_check_is_refused(self):
        run, sink = make_run("port-scanner")
        with self.assertRaises(catalog.UnknownCheck):
            run.finding("SAMMA-PORT-DOES-NOT-EXIST", run.endpoint(port=1))
        with self.assertRaises(catalog.UnknownCheck):
            run.finding("SAMMA-TLS-CERTIFICATE", run.endpoint(port=1))  # other scanner's id
        self.assertEqual(sink.messages, [])

    def test_cve_ids_are_validated_and_normalised(self):
        run, _ = make_run("port-scanner")
        msg = run.finding("SAMMA-PORT-OPEN", run.endpoint(port=80), cve_ids=["cve-2024-6387"])
        self.assertEqual(msg["cveIds"], ["CVE-2024-6387"])
        with self.assertRaises(schema.SchemaError):
            run.finding("SAMMA-PORT-OPEN", run.endpoint(port=80), cve_ids=["GHSA-xxxx"])

    def test_endpoint_port_range(self):
        self.assertEqual(schema.endpoint("h", "443", "https"), {"host": "h", "port": 443, "scheme": "https"})
        self.assertEqual(schema.endpoint("h"), {"host": "h", "port": None, "scheme": None})
        with self.assertRaises(schema.SchemaError):
            schema.endpoint("h", 70000)

    def test_raw_is_made_json_safe(self):
        run, _ = make_run("whois-scanner")
        when = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
        msg = run.finding("SAMMA-WHOIS-RECORD", run.endpoint(scheme="whois"),
                          raw={"when": when, "set": {1}, "nested": {"t": (1, 2)}})
        json.dumps(msg)
        self.assertEqual(msg["raw"]["when"], "2026-01-02T03:04:05Z")
        self.assertEqual(msg["raw"]["nested"]["t"], [1, 2])

    def test_dumps_is_stable(self):
        text = schema.dumps({"b": 1, "a": {"d": 2, "c": 3}})
        self.assertEqual(text, '{"a": {"c": 3,"d": 2},"b": 1}')


class RunShapeTest(unittest.TestCase):
    def test_run_message_shape(self):
        run, sink = make_run("port-scanner")
        run.start()
        body = run.finish("succeeded", "")
        self.assertEqual(set(body), RUN_KEYS)
        self.assertEqual(body["kind"], "run")
        self.assertEqual(body["outcome"], "succeeded")
        self.assertEqual(body["findingCount"], 0)
        self.assertEqual(body["scan"], "done")
        self.assertTrue(RFC3339.match(body["startedAt"]))
        self.assertTrue(RFC3339.match(body["finishedAt"]))
        self.assertTrue(sink.closed)

    def test_outcome_vocabulary(self):
        for outcome in ("succeeded", "failed", "timed_out"):
            run, _ = make_run("port-scanner")
            self.assertEqual(run.finish(outcome)["outcome"], outcome)
        run, _ = make_run("port-scanner")
        with self.assertRaises(schema.SchemaError):
            run.finish("crashed")

    def test_run_message_text_is_capped(self):
        run, _ = make_run("port-scanner")
        body = run.finish("failed", "x" * 5000)
        self.assertLessEqual(len(body["message"].encode("utf-8")), schema.MESSAGE_MAX_BYTES)


class EnvironmentTest(unittest.TestCase):
    def test_scanner_version_from_env(self):
        with mock.patch.dict(os.environ, {"SAMMA_SCANNER_VERSION": "9.9.9"}):
            self.assertEqual(schema.scanner_version(), "9.9.9")

    def test_scanner_version_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "VERSION")
            with open(path, "w") as handle:
                handle.write("3.1.4\n")
            with mock.patch.dict(os.environ, {"SAMMA_SCANNER_VERSION": ""}):
                self.assertEqual(schema.scanner_version(version_files=(path,)), "3.1.4")

    def test_repository_version_file_is_the_fallback(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, "VERSION"), encoding="utf-8") as handle:
            expected = handle.read().strip()
        with mock.patch.dict(os.environ, {"SAMMA_SCANNER_VERSION": ""}):
            self.assertEqual(schema.scanner_version(version_files=("/nonexistent/VERSION",)), expected)

    def test_run_id_prefers_env_then_hostname(self):
        with mock.patch.dict(os.environ, {"SAMMA_RUN_ID": "job-abc-12345"}):
            self.assertEqual(schema.run_id(), "job-abc-12345")
        with mock.patch.dict(os.environ, {"SAMMA_RUN_ID": ""}):
            with mock.patch("socket.gethostname", return_value="tls-scanner-x-28934712-k9z2p"):
                self.assertEqual(schema.run_id(), "tls-scanner-x-28934712-k9z2p")

    def test_rfc3339_converts_to_utc(self):
        from datetime import timedelta
        plus_two = timezone(timedelta(hours=2))
        self.assertEqual(schema.rfc3339(datetime(2026, 10, 24, 14, 0, 0, tzinfo=plus_two)),
                         "2026-10-24T12:00:00Z")
