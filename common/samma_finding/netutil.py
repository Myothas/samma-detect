"""Address resolution and connecting that works for IPv4, IPv6 and dual-stack.

A target may be a hostname with A and/or AAAA records, an IPv4 literal or an
IPv6 literal. ``resolve`` asks for every family (``AF_UNSPEC``) and keeps the
order the resolver returns; ``connect_any`` tries each address until one
accepts the TCP connection. ``endpoint.host`` in a finding stays the name
that was given; the address actually used goes under ``raw``.
"""

import socket

FAMILY_NAMES = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}


class ResolvedAddress(object):
    __slots__ = ("family", "address", "sockaddr")

    def __init__(self, family, address, sockaddr):
        self.family = family
        self.address = address
        self.sockaddr = sockaddr

    @property
    def family_name(self):
        return FAMILY_NAMES.get(self.family, str(self.family))

    def describe(self):
        return {"address": self.address, "family": self.family_name}

    def __repr__(self):
        return "ResolvedAddress(%s %s)" % (self.family_name, self.address)


def resolve(host, port=None, getaddrinfo=socket.getaddrinfo):
    """Every address ``host`` resolves to, both families, duplicates removed.

    Raises ``socket.gaierror`` when the name does not resolve at all, as the
    socket module does; a scanner lets that surface as a failed run.
    """
    infos = getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    seen = set()
    addresses = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family not in FAMILY_NAMES:
            continue
        address = sockaddr[0]
        key = (family, address)
        if key in seen:
            continue
        seen.add(key)
        addresses.append(ResolvedAddress(family, address, sockaddr))
    if not addresses:
        raise socket.gaierror("no IPv4 or IPv6 address for %r" % (host,))
    return addresses


def with_port(resolved, port):
    """A copy of ``resolved`` whose sockaddr points at ``port``."""
    sockaddr = (resolved.sockaddr[0], port) + tuple(resolved.sockaddr[2:])
    return ResolvedAddress(resolved.family, resolved.address, sockaddr)


def connect_any(host, port, timeout, addresses=None, socket_factory=socket.socket):
    """Connect to the first address of ``host`` that accepts; return ``(sock, resolved)``.

    Raises the last error when no address accepts, or ``socket.gaierror``
    when the name does not resolve.
    """
    candidates = addresses if addresses is not None else resolve(host, port)
    last_error = None
    for candidate in candidates:
        candidate = with_port(candidate, port)
        sock = socket_factory(candidate.family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect(candidate.sockaddr)
            return sock, candidate
        except OSError as exc:
            last_error = exc
            sock.close()
    if last_error is None:
        last_error = OSError("no address to connect to for %r" % (host,))
    raise last_error


def probe_port(resolved, port, timeout, socket_factory=socket.socket):
    """``True`` when ``port`` accepts a TCP connection on ``resolved``."""
    candidate = with_port(resolved, port)
    sock = socket_factory(candidate.family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        return sock.connect_ex(candidate.sockaddr) == 0
    finally:
        sock.close()
