"""Where messages go: stdout, the ``/out`` file, and NATS.

The NATS client is imported lazily inside :class:`NatsPublisher` so the
package stays importable (and testable) where ``nats-py`` is not installed.
"""

import os
import sys

from . import schema


class StdoutPublisher:
    """One JSON document per line on stdout (the container log)."""

    def __init__(self, stream=None):
        self.stream = stream

    def publish(self, message):
        stream = self.stream or sys.stdout
        stream.write(schema.dumps(message) + "\n")
        stream.flush()

    def close(self):
        pass


class FilePublisher:
    """Append one JSON document per line to ``<out_dir>/<parser>.json``."""

    def __init__(self, path):
        self.path = path
        self._handle = None

    def publish(self, message):
        if self._handle is None:
            self._handle = open(self.path, "a", encoding="utf-8")
        self._handle.write(schema.dumps(message) + "\n")
        self._handle.flush()

    def close(self):
        if self._handle is not None:
            self._handle.close()
            self._handle = None


class NatsPublisher:
    """Publish every message on one subject over a single NATS connection.

    The v1 parser connected once per message; this keeps the connection
    for the whole run and flushes after each publish so a finding is on the
    server before the next check runs.
    """

    def __init__(self, url, subject):
        self.url = url
        self.subject = subject
        self._loop = None
        self._nc = None

    def _connect(self):
        import asyncio
        import nats  # third-party: nats-py, installed in every image

        self._loop = asyncio.new_event_loop()
        self._nc = self._loop.run_until_complete(nats.connect(self.url))

    def publish(self, message):
        if self._nc is None:
            self._connect()
        payload = schema.dumps(message).encode("utf-8")

        async def _send():
            await self._nc.publish(self.subject, payload)
            await self._nc.flush()

        self._loop.run_until_complete(_send())

    def close(self):
        if self._nc is None:
            return
        try:
            self._loop.run_until_complete(self._nc.drain())
        finally:
            self._loop.close()
            self._nc = None
            self._loop = None


class ListPublisher:
    """Collects messages in memory; the publisher the tests use."""

    def __init__(self):
        self.messages = []
        self.closed = False

    def publish(self, message):
        self.messages.append(message)

    def close(self):
        self.closed = True


class Emitter:
    """Fan one message out to every configured publisher."""

    def __init__(self, publishers):
        self.publishers = list(publishers)

    @classmethod
    def from_env(cls, scanner, environ=None):
        """Build the publishers the v1 parser's environment variables select.

        ``WRITE_TO_FILE`` (anything but ``False``), ``PARSER``, ``OUT_DIR``,
        ``NATS_ENABLED`` (anything but ``False``), ``NATS_URL``,
        ``NATS_SUBJECT``. Stdout is always on.
        """
        env = os.environ if environ is None else environ
        publishers = [StdoutPublisher()]
        if env.get("WRITE_TO_FILE", "False") != "False":
            out_dir = env.get("OUT_DIR", "/out")
            parser = env.get("PARSER", scanner)
            publishers.append(FilePublisher(os.path.join(out_dir, "%s.json" % parser)))
        if env.get("NATS_ENABLED", "False") != "False":
            publishers.append(NatsPublisher(
                env.get("NATS_URL", "nats://localhost:4222"),
                env.get("NATS_SUBJECT", "samma-io.scan"),
            ))
        return cls(publishers)

    def emit(self, message):
        for publisher in self.publishers:
            publisher.publish(message)

    def close(self):
        errors = []
        for publisher in self.publishers:
            try:
                publisher.close()
            except Exception as exc:  # one broken sink must not hide the others
                errors.append(exc)
        if errors:
            raise errors[0]
