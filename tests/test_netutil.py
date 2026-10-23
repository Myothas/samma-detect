import socket
import unittest

from samma_finding import netutil


def fake_getaddrinfo(host, port, family=0, socktype=0, proto=0, flags=0):
    """A dual-stack host: AAAA first, then A, with a duplicate the resolver may return."""
    return [
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::10", port or 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port or 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port or 0)),
    ]


class FakeSocket(object):
    """Accepts only the families listed in ``accept``."""

    def __init__(self, family, socktype, accept, log):
        self.family = family
        self.accept = accept
        self.log = log
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def connect(self, sockaddr):
        self.log.append((self.family, sockaddr))
        if self.family not in self.accept:
            raise ConnectionRefusedError(111, "Connection refused")

    def connect_ex(self, sockaddr):
        self.log.append((self.family, sockaddr))
        return 0 if self.family in self.accept else 111

    def close(self):
        pass


def factory(accept, log):
    return lambda family, socktype: FakeSocket(family, socktype, accept, log)


class ResolveTest(unittest.TestCase):
    def test_dual_stack_hostname_keeps_both_families_and_order(self):
        addresses = netutil.resolve("dual.example", 443, getaddrinfo=fake_getaddrinfo)
        self.assertEqual([a.family_name for a in addresses], ["ipv6", "ipv4"])
        self.assertEqual([a.address for a in addresses], ["2001:db8::10", "192.0.2.10"])
        self.assertEqual(addresses[0].sockaddr, ("2001:db8::10", 443, 0, 0))
        self.assertEqual(addresses[0].describe(), {"address": "2001:db8::10", "family": "ipv6"})

    def test_ipv6_literal_resolves_without_dns(self):
        addresses = netutil.resolve("2001:db8::1", 443)
        self.assertEqual(len(addresses), 1)
        self.assertEqual(addresses[0].family, socket.AF_INET6)
        self.assertEqual(addresses[0].sockaddr[:2], ("2001:db8::1", 443))

    def test_ipv4_literal_resolves_without_dns(self):
        addresses = netutil.resolve("192.0.2.1", 80)
        self.assertEqual([(a.family, a.address) for a in addresses], [(socket.AF_INET, "192.0.2.1")])

    def test_unknown_name_raises_gaierror(self):
        def no_such(*args, **kwargs):
            raise socket.gaierror(-2, "Name or service not known")
        with self.assertRaises(socket.gaierror):
            netutil.resolve("nope.invalid", 80, getaddrinfo=no_such)

    def test_only_unknown_families_raises_gaierror(self):
        def odd(*args, **kwargs):
            return [(socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "/tmp/x")]
        with self.assertRaises(socket.gaierror):
            netutil.resolve("x", 80, getaddrinfo=odd)

    def test_with_port_keeps_scope_id(self):
        resolved = netutil.ResolvedAddress(socket.AF_INET6, "fe80::1", ("fe80::1", 0, 0, 3))
        self.assertEqual(netutil.with_port(resolved, 22).sockaddr, ("fe80::1", 22, 0, 3))


class ConnectTest(unittest.TestCase):
    def setUp(self):
        self.addresses = netutil.resolve("dual.example", None, getaddrinfo=fake_getaddrinfo)

    def test_falls_back_from_ipv6_to_ipv4(self):
        log = []
        sock, used = netutil.connect_any("dual.example", 443, 2.0, addresses=self.addresses,
                                         socket_factory=factory({socket.AF_INET}, log))
        self.assertEqual(used.family, socket.AF_INET)
        self.assertEqual(used.sockaddr, ("192.0.2.10", 443))
        self.assertEqual(log, [(socket.AF_INET6, ("2001:db8::10", 443, 0, 0)),
                               (socket.AF_INET, ("192.0.2.10", 443))])
        self.assertEqual(sock.timeout, 2.0)

    def test_ipv6_first_when_it_accepts(self):
        log = []
        _sock, used = netutil.connect_any("dual.example", 443, 1, addresses=self.addresses,
                                          socket_factory=factory({socket.AF_INET6, socket.AF_INET}, log))
        self.assertEqual(used.family_name, "ipv6")
        self.assertEqual(len(log), 1)

    def test_all_refused_raises_the_last_error(self):
        with self.assertRaises(ConnectionRefusedError):
            netutil.connect_any("dual.example", 443, 1, addresses=self.addresses,
                                socket_factory=factory(set(), []))

    def test_probe_port_per_address(self):
        v6, v4 = self.addresses
        log = []
        self.assertFalse(netutil.probe_port(v6, 22, 1, socket_factory=factory({socket.AF_INET}, log)))
        self.assertTrue(netutil.probe_port(v4, 22, 1, socket_factory=factory({socket.AF_INET}, log)))
        self.assertEqual(log[1], (socket.AF_INET, ("192.0.2.10", 22)))
