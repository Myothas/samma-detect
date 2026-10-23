"""The run wrapper every scanner's ``main`` goes through.

``main(scanner, scan)`` reads ``TARGET``, builds the publishers from the
environment, calls ``scan(run)`` and ends the run exactly once:

* the scan returns: ``outcome=succeeded``;
* the scan raises: ``outcome=failed`` with the exception class and its short
  message, no stack trace;
* the process gets SIGTERM (a Job deadline, an eviction): ``outcome=timed_out``.

The ``/out/die`` file is still written for the Filebeat sidecar.
"""

import os
import signal
import sys
import time

from . import catalog, schema
from .output import Emitter

EXIT_SUCCEEDED = 0
EXIT_FAILED = 1
EXIT_NO_TARGET = 2
EXIT_TIMED_OUT = 128 + signal.SIGTERM


class ScanTimedOut(BaseException):
    """Raised in the main thread when SIGTERM arrives.

    A ``BaseException`` so a scanner's own ``except Exception`` does not
    swallow it.
    """


class Run(object):
    """One scan of one target by one scanner."""

    def __init__(self, scanner, target, emitter, version=None, run=None, clock=None):
        self.scanner = scanner
        self.target = target
        self.emitter = emitter
        self.version = version or schema.scanner_version()
        self.id = run or schema.run_id()
        self._clock = clock or schema.utc_now
        self.started_at = None
        self.finished_at = None
        self.outcome = None
        self.message = ""
        self.finding_count = 0
        self._finished = False
        self._wall_start = None

    # -- findings ---------------------------------------------------------

    def endpoint(self, host=None, port=None, scheme=None):
        return schema.endpoint(self.target if host is None else host, port, scheme)

    def finding(self, check_id, endpoint, evidence="", raw=None, cve_ids=()):
        """Emit one finding for ``check_id`` from this scanner's catalogue."""
        check = catalog.get(self.scanner, check_id)
        message = schema.build_finding(
            self.scanner, self.target, self.id, self.version, check, check_id,
            endpoint, evidence=evidence, raw=raw, cve_ids=cve_ids,
            emitted_at=self._clock(),
        )
        self.emitter.emit(message)
        self.finding_count += 1
        return message

    # -- lifecycle --------------------------------------------------------

    def start(self):
        self.started_at = self._clock()
        self._wall_start = time.monotonic()

    def elapsed(self):
        if self._wall_start is None:
            return 0.0
        return time.monotonic() - self._wall_start

    def finish(self, outcome, message=""):
        """Emit the run message once and close the publishers."""
        if self._finished:
            return None
        self._finished = True
        if self.started_at is None:
            self.start()
        self.finished_at = self._clock()
        self.outcome = outcome
        self.message = message
        body = schema.build_run(
            self.scanner, self.target, self.id, self.version, outcome, message,
            self.started_at, self.finished_at, self.finding_count,
        )
        try:
            self.emitter.emit(body)
        finally:
            self.emitter.close()
        return body

    def execute(self, scan):
        """Run ``scan(self)`` under the outcome rules; return the exit code."""
        self.start()
        previous = _install_sigterm_handler()
        code = EXIT_SUCCEEDED
        try:
            try:
                scan(self)
                outcome, message = schema.OUTCOME_SUCCEEDED, ""
            except ScanTimedOut as exc:
                outcome, message = schema.OUTCOME_TIMED_OUT, str(exc)
                code = EXIT_TIMED_OUT
            except KeyboardInterrupt:
                outcome, message = schema.OUTCOME_FAILED, "KeyboardInterrupt"
                code = EXIT_FAILED
            except Exception as exc:
                outcome, message = schema.OUTCOME_FAILED, describe_exception(exc)
                code = EXIT_FAILED
            try:
                self.finish(outcome, message)
            except Exception as exc:
                sys.stderr.write("ERROR: could not publish the run message: %s\n"
                                 % describe_exception(exc))
                code = EXIT_FAILED
        finally:
            _restore_sigterm_handler(previous)
        return code


def describe_exception(exc):
    """``ClassName: short message``, never a traceback."""
    text = str(exc).strip()
    name = type(exc).__name__
    return "%s: %s" % (name, text) if text else name


def _install_sigterm_handler():
    def _on_sigterm(signum, frame):
        raise ScanTimedOut("SIGTERM received")
    try:
        return signal.signal(signal.SIGTERM, _on_sigterm)
    except (ValueError, OSError):  # not the main thread, or no signals here
        return None


def _restore_sigterm_handler(previous):
    if previous is None:
        return
    try:
        signal.signal(signal.SIGTERM, previous)
    except (ValueError, OSError):
        pass


def write_die_file(out_dir=None):
    """Tell the sidecar the scan is over; best effort, as /out may not exist."""
    out_dir = out_dir or os.getenv("OUT_DIR", "/out")
    if not os.path.isdir(out_dir):
        return False
    try:
        with open(os.path.join(out_dir, "die"), "w") as handle:
            handle.write("time to die")
        return True
    except OSError:
        return False


def main(scanner, scan, target=None, emitter=None, argv_exit=True):
    """Entry point for a scanner's ``if __name__ == "__main__"`` block."""
    if target is None:
        target = os.getenv("TARGET", "").strip()
    if not target:
        sys.stderr.write("ERROR: TARGET environment variable is required\n")
        if argv_exit:
            sys.exit(EXIT_NO_TARGET)
        return EXIT_NO_TARGET
    if emitter is None:
        emitter = Emitter.from_env(scanner)
    run = Run(scanner, target, emitter)
    code = run.execute(scan)
    write_die_file()
    if argv_exit:
        sys.exit(code)
    return code
