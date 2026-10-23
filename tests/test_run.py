import io
import os
import signal
import tempfile
import time
import unittest
from unittest import mock

from samma_finding import Emitter, ListPublisher, legacy, run as runmod
from samma_finding.output import FilePublisher, NatsPublisher, StdoutPublisher
from .helpers import execute, make_run


def _emit_two(run):
    run.finding("SAMMA-PORT-OPEN", run.endpoint(port=80, scheme="http"), evidence="a")
    run.finding("SAMMA-PORT-OPEN-ADMIN", run.endpoint(port=22, scheme="ssh"), evidence="b")


class OutcomeTest(unittest.TestCase):
    def test_success(self):
        code, findings, body = execute("port-scanner", _emit_two)
        self.assertEqual(code, runmod.EXIT_SUCCEEDED)
        self.assertEqual(len(findings), 2)
        self.assertEqual(body["outcome"], "succeeded")
        self.assertEqual(body["message"], "")
        self.assertEqual(body["findingCount"], 2)

    def test_exception_is_a_failed_run_with_the_class_name_only(self):
        def scan(run):
            _emit_two(run)
            raise ConnectionRefusedError(111, "Connection refused")

        code, findings, body = execute("port-scanner", scan)
        self.assertEqual(code, runmod.EXIT_FAILED)
        self.assertEqual(len(findings), 2, "findings before the crash are kept")
        self.assertEqual(body["outcome"], "failed")
        self.assertTrue(body["message"].startswith("ConnectionRefusedError"), body["message"])
        self.assertNotIn("Traceback", body["message"])
        self.assertNotIn("\n", body["message"])
        self.assertEqual(body["findingCount"], 2)

    def test_exception_without_text(self):
        class Odd(Exception):
            pass

        def scan(run):
            raise Odd()

        _code, _findings, body = execute("port-scanner", scan)
        self.assertEqual(body["message"], "Odd")

    def test_sigterm_is_a_timed_out_run(self):
        def scan(run):
            run.finding("SAMMA-PORT-OPEN", run.endpoint(port=80))
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(2)  # the handler raises before this returns
            raise AssertionError("SIGTERM did not interrupt the scan")

        previous = signal.getsignal(signal.SIGTERM)
        code, findings, body = execute("port-scanner", scan)
        self.assertEqual(code, runmod.EXIT_TIMED_OUT)
        self.assertEqual(len(findings), 1)
        self.assertEqual(body["outcome"], "timed_out")
        self.assertIn("SIGTERM", body["message"])
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous, "handler restored")

    def test_a_scanner_catching_exception_cannot_swallow_the_timeout(self):
        def scan(run):
            try:
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(2)
            except Exception:  # noqa: BLE001 - the point of the test
                pass

        code, _findings, body = execute("port-scanner", scan)
        self.assertEqual(body["outcome"], "timed_out")
        self.assertEqual(code, runmod.EXIT_TIMED_OUT)

    def test_keyboard_interrupt_is_failed(self):
        def scan(run):
            raise KeyboardInterrupt()

        code, _f, body = execute("port-scanner", scan)
        self.assertEqual((code, body["outcome"], body["message"]),
                         (runmod.EXIT_FAILED, "failed", "KeyboardInterrupt"))

    def test_run_message_is_sent_exactly_once(self):
        run, sink = make_run("port-scanner")
        run.start()
        first = run.finish("succeeded")
        second = run.finish("failed", "again")
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual([m["kind"] for m in sink.messages], ["run"])
        self.assertEqual(run.outcome, "succeeded")

    def test_publish_failure_at_the_end_is_reported_and_non_zero(self):
        class Flaky(ListPublisher):
            def publish(self, message):
                if message["kind"] == "run":
                    raise OSError("nats down")
                super().publish(message)

        from samma_finding import Run
        sink = Flaky()
        run = Run("port-scanner", "example.com", Emitter([sink]), version="t", run="r")
        with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
            code = run.execute(_emit_two)
        self.assertEqual(code, runmod.EXIT_FAILED)
        self.assertIn("could not publish the run message", err.getvalue())
        self.assertIn("OSError", err.getvalue())
        self.assertTrue(sink.closed, "publishers are closed even when the last publish fails")


class MainTest(unittest.TestCase):
    def test_missing_target_exits_2_without_messages(self):
        with mock.patch.dict(os.environ, {"TARGET": ""}):
            with mock.patch("sys.stderr", new_callable=io.StringIO) as err:
                code = runmod.main("port-scanner", _emit_two, argv_exit=False)
        self.assertEqual(code, runmod.EXIT_NO_TARGET)
        self.assertIn("TARGET", err.getvalue())

    def test_main_runs_and_writes_the_die_file(self):
        sink = ListPublisher()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"OUT_DIR": tmp}):
                code = runmod.main("port-scanner", _emit_two, target="example.com",
                                   emitter=Emitter([sink]), argv_exit=False)
            self.assertTrue(os.path.exists(os.path.join(tmp, "die")))
        self.assertEqual(code, 0)
        self.assertEqual([m["kind"] for m in sink.messages], ["finding", "finding", "run"])
        self.assertEqual(sink.messages[-1]["target"], "example.com")

    def test_die_file_is_best_effort(self):
        self.assertFalse(runmod.write_die_file("/nonexistent/dir/for/samma"))


class EmitterTest(unittest.TestCase):
    def test_from_env_stdout_only_by_default(self):
        emitter = Emitter.from_env("port-scanner", environ={})
        self.assertEqual([type(p) for p in emitter.publishers], [StdoutPublisher])

    def test_from_env_file_and_nats(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"WRITE_TO_FILE": "true", "OUT_DIR": tmp, "PARSER": "custom",
                   "NATS_ENABLED": "true", "NATS_URL": "nats://n:4222", "NATS_SUBJECT": "samma-io.scan"}
            emitter = Emitter.from_env("port-scanner", environ=env)
            kinds = [type(p) for p in emitter.publishers]
            self.assertEqual(kinds, [StdoutPublisher, FilePublisher, NatsPublisher])
            self.assertEqual(emitter.publishers[1].path, os.path.join(tmp, "custom.json"))
            self.assertEqual((emitter.publishers[2].url, emitter.publishers[2].subject),
                             ("nats://n:4222", "samma-io.scan"))
            # Nothing connects until the first publish, so the client import is lazy.
            self.assertIsNone(emitter.publishers[2]._nc)

    def test_file_publisher_appends_json_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.json")
            publisher = FilePublisher(path)
            publisher.publish({"b": 1})
            publisher.publish({"a": "é"})
            publisher.close()
            with open(path, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        self.assertEqual(lines, ['{"b": 1}', '{"a": "é"}'])

    def test_stdout_publisher_prints_json(self):
        stream = io.StringIO()
        StdoutPublisher(stream).publish({"k": "v"})
        self.assertEqual(stream.getvalue(), '{"k": "v"}\n')


class LegacyShimTest(unittest.TestCase):
    def test_logger_and_endthis_keep_the_v1_shape(self):
        sink = ListPublisher()
        with mock.patch.object(legacy, "_emitter", Emitter([sink])):
            with mock.patch.dict(os.environ, {"SAMMA_IO_SCANNER": "port-scanner", "OUT_DIR": "/nonexistent"}):
                legacy.logger({"host": "example.com", "port": 80, "status": "open", "type": "PortScan"})
                legacy.endThis()
        self.assertEqual(sink.messages[0]["samma-io"]["scanner"], "port-scanner")
        self.assertEqual(sink.messages[0]["host"], "example.com")
        self.assertNotIn("schema", sink.messages[0], "the legacy API emits v1 records")
        self.assertEqual(sink.messages[1]["scan"], "done")
        self.assertTrue(sink.closed)

    def test_every_scanner_ships_the_shim(self):
        from .helpers import SCANNERS
        from . import REPO_ROOT
        for scanner in SCANNERS:
            path = os.path.join(REPO_ROOT, scanner, "code", "sammaParser.py")
            with open(path) as handle:
                self.assertIn("from samma_finding.legacy import", handle.read(), scanner)
