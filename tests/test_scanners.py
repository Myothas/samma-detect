"""Each scanner's classification, driven through fakes: no network, no
third-party modules."""

import email.message
import io
import socket
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone

from samma_finding import netutil
from .helpers import execute, load_scanner, make_run

V6 = netutil.ResolvedAddress(socket.AF_INET6, "2001:db8::10", ("2001:db8::10", 0, 0, 0))
V4 = netutil.ResolvedAddress(socket.AF_INET, "192.0.2.10", ("192.0.2.10", 0))


def ids(findings):
    return [f["checkId"] for f in findings]


class PortScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("port-scanner")

    def test_settings_precedence(self):
        self.assertEqual(self.mod.settings({"PORT": "22"}, cfg={})["ports"], [22])
        self.assertEqual(self.mod.settings({"PORTS": "80, 443,"}, cfg={})["ports"], [80, 443])
        self.assertEqual(self.mod.settings({}, cfg={"defaults": {"ports": [1, 2], "timeout": 7}}),
                         {"ports": [1, 2], "timeout": 7.0})
        self.assertEqual(self.mod.settings({}, cfg={})["ports"], [80, 443, 8080, 8443])

    def test_dual_stack_open_ports_become_one_finding_per_port(self):
        open_on = {(443, "ipv6"), (443, "ipv4"), (22, "ipv4")}

        def probe(address, port, timeout):
            return (port, address.family_name) in open_on

        opts = {"ports": [443, 22, 8080], "timeout": 1}
        code, findings, body = execute(
            "port-scanner",
            lambda run: self.mod.scan(run, opts, resolve=lambda host: [V6, V4], probe=probe),
            target="dual.example")
        self.assertEqual(code, 0)
        self.assertEqual(ids(findings), ["SAMMA-PORT-OPEN", "SAMMA-PORT-OPEN-ADMIN"])
        https, ssh = findings
        self.assertEqual(https["endpoint"], {"host": "dual.example", "port": 443, "scheme": "https"})
        self.assertEqual([a["status"] for a in https["raw"]["addresses"]], ["open", "open"])
        self.assertEqual(ssh["severity"], "HIGH")
        self.assertEqual(ssh["endpoint"]["scheme"], "ssh")
        self.assertIn("192.0.2.10 (ipv4)", ssh["evidence"])
        self.assertNotIn("2001:db8::10", ssh["evidence"], "closed addresses are not evidence")
        self.assertEqual([a["status"] for a in ssh["raw"]["addresses"]], ["closed", "open"])
        self.assertEqual((ssh["host"], ssh["port"], ssh["status"], ssh["type"]),
                         ("dual.example", 22, "open", "PortScan"))
        self.assertEqual(body["findingCount"], 2)

    def test_ipv6_literal_target(self):
        literal = netutil.resolve("2001:db8::1", None)
        seen = []

        def probe(address, port, timeout):
            seen.append((address.family, port))
            return True

        _code, findings, _body = execute(
            "port-scanner",
            lambda run: self.mod.scan(run, {"ports": [80], "timeout": 1},
                                      resolve=lambda host: literal, probe=probe),
            target="2001:db8::1")
        self.assertEqual(seen, [(socket.AF_INET6, 80)])
        self.assertEqual(findings[0]["endpoint"]["host"], "2001:db8::1")
        self.assertEqual(findings[0]["raw"]["addresses"][0]["family"], "ipv6")

    def test_unresolvable_target_is_a_failed_run(self):
        def resolve(host):
            raise socket.gaierror(-2, "Name or service not known")

        code, findings, body = execute(
            "port-scanner",
            lambda run: self.mod.scan(run, {"ports": [80], "timeout": 1}, resolve=resolve))
        self.assertEqual((code, findings, body["outcome"]), (1, [], "failed"))
        self.assertTrue(body["message"].startswith("gaierror"), body["message"])


class TlsScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("tls-scanner")
        self.now = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)

    def cert(self, days):
        not_after = self.now + timedelta(days=days)
        return self.mod.parse_certificate({
            "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "Let's Encrypt"),),),
        }, now=self.now)

    def obs(self, **kwargs):
        base = {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
                "cert": self.cert(60), "verify_error": None, "protocol_error": None}
        base.update(kwargs)
        return base

    def test_parse_certificate(self):
        cert = self.cert(42)
        self.assertEqual((cert["days_remaining"], cert["expired"], cert["subject_cn"], cert["issuer"]),
                         (42, False, "example.com", "Let's Encrypt"))

    def test_healthy_endpoint_is_inventory_only(self):
        findings = self.mod.classify(self.obs())
        self.assertEqual([f[0] for f in findings], ["SAMMA-TLS-CERTIFICATE"])
        self.assertIn("issuer=Let's Encrypt", findings[0][1])

    def test_deprecated_protocol_and_weak_cipher(self):
        found = dict(self.mod.classify(self.obs(protocol="TLSv1", cipher="DES-CBC3-SHA")))
        self.assertIn("SAMMA-TLS-PROTOCOL-DEPRECATED", found)
        self.assertIn("SAMMA-TLS-CIPHER-WEAK", found)
        self.assertEqual(found["SAMMA-TLS-PROTOCOL-DEPRECATED"], "negotiated TLSv1")
        for strong in ("ECDHE-RSA-AES128-GCM-SHA256", "TLS_CHACHA20_POLY1305_SHA256"):
            self.assertFalse(self.mod.is_weak_cipher(strong), strong)
        for weak in ("RC4-SHA", "NULL-MD5", "EXP-RC2-CBC-MD5", "ADH-AES128-SHA"):
            self.assertTrue(self.mod.is_weak_cipher(weak), weak)

    def test_server_too_old_to_negotiate(self):
        found = dict(self.mod.classify(self.obs(protocol=None, cipher=None, cert=None,
                                                protocol_error="UNSUPPORTED_PROTOCOL")))
        self.assertEqual(list(found), ["SAMMA-TLS-PROTOCOL-DEPRECATED"])

    def test_expiry(self):
        self.assertIn("SAMMA-TLS-CERT-EXPIRING", dict(self.mod.classify(self.obs(cert=self.cert(10)))))
        self.assertNotIn("SAMMA-TLS-CERT-EXPIRING", dict(self.mod.classify(self.obs(cert=self.cert(15)))))
        expired = dict(self.mod.classify(self.obs(cert=self.cert(-3))))
        self.assertIn("SAMMA-TLS-CERT-EXPIRED", expired)
        self.assertIn("3 days ago", expired["SAMMA-TLS-CERT-EXPIRED"])

    def test_verification_errors(self):
        invalid = dict(self.mod.classify(self.obs(protocol=None, cipher=None, cert=None,
                                                  verify_error="self-signed certificate")))
        self.assertEqual(list(invalid), ["SAMMA-TLS-CERT-INVALID"])
        expired = dict(self.mod.classify(self.obs(protocol=None, cipher=None, cert=None,
                                                  verify_error="certificate has expired")))
        self.assertEqual(list(expired), ["SAMMA-TLS-CERT-EXPIRED"])

    def test_connection_refused_is_a_failed_run(self):
        def connect(host, port, timeout):
            raise ConnectionRefusedError(111, "Connection refused")

        opts = {"port": 443, "timeout": 1, "verify_cert": True}
        code, findings, body = execute("tls-scanner", lambda run: self.mod.scan(run, opts, connect=connect))
        self.assertEqual((code, findings, body["outcome"]), (1, [], "failed"))
        self.assertIn("ConnectionRefusedError", body["message"])

    def test_settings(self):
        opts = self.mod.settings({"VERIFY_CERT": "false", "PORT": "8443"}, cfg={})
        self.assertEqual((opts["port"], opts["verify_cert"], opts["timeout"]), (8443, False, 5.0))


class HttpHeadersScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("http-headers-scanner")

    def test_nothing_set_over_https(self):
        found = [f[0] for f in self.mod.classify({}, https=True, status_code=200)]
        self.assertEqual(found, [
            "SAMMA-HEADERS-HSTS-MISSING", "SAMMA-HEADERS-CSP-MISSING",
            "SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING", "SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING",
            "SAMMA-HEADERS-REFERRER-POLICY-MISSING", "SAMMA-HEADERS-PERMISSIONS-POLICY-MISSING",
            "SAMMA-HEADERS-OBSERVED"])

    def test_hsts_is_not_judged_over_plain_http(self):
        found = [f[0] for f in self.mod.classify({}, https=False)]
        self.assertNotIn("SAMMA-HEADERS-HSTS-MISSING", found)

    def test_csp_frame_ancestors_supersedes_x_frame_options(self):
        headers = {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"}
        found = [f[0] for f in self.mod.classify(headers, https=False)]
        self.assertNotIn("SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING", found)
        self.assertNotIn("SAMMA-HEADERS-CSP-MISSING", found)

    def test_deprecated_xss_filter_enabled(self):
        found = dict((f[0], f[1]) for f in self.mod.classify({"x-xss-protection": "1; mode=block"}, https=False))
        self.assertIn("SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED", found)
        found = [f[0] for f in self.mod.classify({"x-xss-protection": "0"}, https=False)]
        self.assertNotIn("SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED", found)

    def test_all_set_is_inventory_only(self):
        headers = {h: "x" for h in self.mod.SECURITY_HEADERS}
        headers["x-xss-protection"] = "0"
        findings = self.mod.classify(headers, https=True, status_code=200)
        self.assertEqual([f[0] for f in findings], ["SAMMA-HEADERS-OBSERVED"])
        self.assertIn("missing: none", findings[0][1])

    def test_scan_shapes(self):
        headers = {"strict-transport-security": "max-age=31536000", "x-frame-options": "DENY"}
        opts = {"https": True, "port": 443, "timeout": 1}
        code, findings, _body = execute(
            "http-headers-scanner",
            lambda run: self.mod.scan(run, opts, fetch_=lambda target, o: (200, headers)))
        self.assertEqual(code, 0)
        by_id = {f["checkId"]: f for f in findings}
        csp = by_id["SAMMA-HEADERS-CSP-MISSING"]
        self.assertEqual(csp["endpoint"], {"host": "example.com", "port": 443, "scheme": "https"})
        self.assertEqual(csp["raw"]["header"], "content-security-policy")
        self.assertFalse(csp["raw"]["present"])
        self.assertEqual(csp["raw"]["status_code"], 200)
        observed = by_id["SAMMA-HEADERS-OBSERVED"]
        self.assertEqual(observed["raw"]["headers"]["x-frame-options"], "DENY")
        self.assertIn("present: strict-transport-security=max-age=31536000", observed["evidence"])

    def test_connection_error_is_a_failed_run(self):
        def fetch_(target, opts):
            raise socket.timeout("timed out")
        opts = {"https": False, "port": 80, "timeout": 1}
        code, _f, body = execute("http-headers-scanner", lambda run: self.mod.scan(run, opts, fetch_=fetch_))
        self.assertEqual((code, body["outcome"]), (1, "failed"))


class FakeOpener(object):
    """``responses`` maps a URL to an int status or to ``(redirect_code, location)``;
    an exception instance is raised."""

    def __init__(self, responses):
        self.responses = responses

    def open(self, url, timeout=None):
        answer = self.responses[url]
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, tuple):
            code, location = answer
            headers = email.message.Message()
            headers["Location"] = location
            raise urllib.error.HTTPError(url, code, "Moved", headers, io.BytesIO())
        if answer >= 400:
            raise urllib.error.HTTPError(url, answer, "Error", email.message.Message(), io.BytesIO())

        class Resp(object):
            status = answer
        return Resp()


class HttpRedirectScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("http-redirect-scanner")
        self.opts = {"timeout": 1, "max_redirects": 4}

    def run_chain(self, target, responses):
        return execute("http-redirect-scanner",
                       lambda run: self.mod.scan(run, self.opts, opener=FakeOpener(responses)),
                       target=target)

    def test_to_url(self):
        self.assertEqual(self.mod.to_url("example.com"), "http://example.com")
        self.assertEqual(self.mod.to_url("https://example.com/x"), "https://example.com/x")
        self.assertEqual(self.mod.to_url("2001:db8::1"), "http://[2001:db8::1]")

    def test_http_to_https_is_inventory_only(self):
        code, findings, _b = self.run_chain("example.com", {
            "http://example.com": (301, "https://example.com/"),
            "https://example.com/": 200})
        self.assertEqual(code, 0)
        self.assertEqual(ids(findings), ["SAMMA-REDIRECT-CHAIN"])
        self.assertEqual(findings[0]["endpoint"], {"host": "example.com", "port": 80, "scheme": "http"})
        self.assertEqual(findings[0]["raw"]["hops"][0]["redirect_to"], "https://example.com/")

    def test_plain_http_final_is_https_missing(self):
        _c, findings, _b = self.run_chain("example.com", {"http://example.com": 200})
        self.assertEqual(ids(findings), ["SAMMA-REDIRECT-HTTPS-MISSING", "SAMMA-REDIRECT-CHAIN"])
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_relative_location_is_resolved(self):
        _c, findings, _b = self.run_chain("example.com", {
            "http://example.com": (302, "/login"),
            "http://example.com/login": 200})
        self.assertEqual(findings[-1]["raw"]["hops"][1]["url"], "http://example.com/login")

    def test_downgrade_and_offsite(self):
        _c, findings, _b = self.run_chain("https://shop.example", {
            "https://shop.example": (302, "http://cdn.other.net/"),
            "http://cdn.other.net/": 200})
        self.assertEqual(ids(findings), ["SAMMA-REDIRECT-DOWNGRADE", "SAMMA-REDIRECT-OFFSITE",
                                         "SAMMA-REDIRECT-CHAIN"])
        self.assertEqual(findings[0]["endpoint"], {"host": "shop.example", "port": 443, "scheme": "https"})

    def test_www_is_the_same_site(self):
        _c, findings, _b = self.run_chain("example.com", {
            "http://example.com": (301, "https://www.example.com/"),
            "https://www.example.com/": 200})
        self.assertNotIn("SAMMA-REDIRECT-OFFSITE", ids(findings))

    def test_loop_is_too_many(self):
        _c, findings, _b = self.run_chain("a.example", {
            "http://a.example": (302, "http://a.example/b"),
            "http://a.example/b": (302, "http://a.example")})
        self.assertIn("SAMMA-REDIRECT-TOO-MANY", ids(findings))
        self.assertNotIn("SAMMA-REDIRECT-HTTPS-MISSING", ids(findings), "no final response to judge")

    def test_broken_hop_is_a_finding_but_a_dead_start_is_a_failed_run(self):
        _c, findings, _b = self.run_chain("a.example", {
            "http://a.example": (301, "https://gone.example/"),
            "https://gone.example/": urllib.error.URLError("Name or service not known")})
        self.assertIn("SAMMA-REDIRECT-BROKEN", ids(findings))
        code, findings, body = self.run_chain("a.example", {
            "http://a.example": urllib.error.URLError("connection refused")})
        self.assertEqual((code, findings, body["outcome"]), (1, [], "failed"))
        self.assertTrue(body["message"].startswith("URLError"))


class DnsScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("dns-scanner")
        self.opts = {"record_types": ["A", "AAAA", "MX", "TXT"]}

    def test_records_become_one_inventory_finding(self):
        answers = {"A": ["192.0.2.1"], "AAAA": None, "MX": ["10 mail.example.com."], "TXT": ['"v=spf1 -all"']}
        code, findings, _b = execute("dns-scanner",
                                     lambda run: self.mod.scan(run, self.opts, query=lambda t, r: answers[r]))
        self.assertEqual(code, 0)
        self.assertEqual(ids(findings), ["SAMMA-DNS-RECORDS"])
        self.assertEqual(findings[0]["endpoint"], {"host": "example.com", "port": None, "scheme": "dns"})
        self.assertIn("AAAA: none", findings[0]["evidence"])
        self.assertIn("A: 192.0.2.1", findings[0]["evidence"])
        self.assertEqual(len(findings[0]["raw"]["records"]), 4)

    def test_nxdomain(self):
        def query(target, rtype):
            raise self.mod.NameDoesNotExist(target)
        _c, findings, body = execute("dns-scanner", lambda run: self.mod.scan(run, self.opts, query=query))
        self.assertEqual(ids(findings), ["SAMMA-DNS-NXDOMAIN"])
        self.assertEqual(body["outcome"], "succeeded")

    def test_partial_errors_are_evidence_but_total_failure_fails_the_run(self):
        def partial(target, rtype):
            if rtype == "TXT":
                raise TimeoutError("timed out")
            return ["x"]
        _c, findings, body = execute("dns-scanner", lambda run: self.mod.scan(run, self.opts, query=partial))
        self.assertEqual(body["outcome"], "succeeded")
        self.assertIn("TXT: error TimeoutError", findings[0]["evidence"])

        def total(target, rtype):
            raise TimeoutError("timed out")
        code, findings, body = execute("dns-scanner", lambda run: self.mod.scan(run, self.opts, query=total))
        self.assertEqual((code, findings, body["outcome"]), (1, [], "failed"))
        self.assertTrue(body["message"].startswith("LookupError"))

    def test_settings(self):
        self.assertEqual(self.mod.settings({"RECORD_TYPES": "a, mx"}, cfg={})["record_types"], ["A", "MX"])


class SshBannerScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("ssh-banner-scanner")
        self.opts = {"port": 22, "timeout": 1}

    def test_classify(self):
        self.assertEqual([f[0] for f in self.mod.classify("SSH-2.0-OpenSSH_9.6")], ["SAMMA-SSH-BANNER"])
        old = [f[0] for f in self.mod.classify("SSH-2.0-OpenSSH_7.4")]
        self.assertEqual(old, ["SAMMA-SSH-VERSION-OUTDATED", "SAMMA-SSH-BANNER"])
        v1 = [f[0] for f in self.mod.classify("SSH-1.99-OpenSSH_8.9p1 Ubuntu-3")]
        self.assertEqual(v1, ["SAMMA-SSH-PROTOCOL-V1", "SAMMA-SSH-BANNER"])
        self.assertEqual(self.mod.parse_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")["software"], "OpenSSH_8.9p1")
        self.assertEqual(self.mod.classify(""), [])

    def test_banner_read(self):
        class Sock(object):
            def recv(self, n):
                return b"SSH-2.0-OpenSSH_7.9p1 Debian-10\r\n"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        _c, findings, _b = execute(
            "ssh-banner-scanner",
            lambda run: self.mod.scan(run, self.opts, connect=lambda h, p, t: (Sock(), V4)))
        self.assertEqual(ids(findings), ["SAMMA-SSH-VERSION-OUTDATED", "SAMMA-SSH-BANNER"])
        self.assertEqual(findings[0]["endpoint"], {"host": "example.com", "port": 22, "scheme": "ssh"})
        self.assertEqual(findings[0]["raw"]["software"], "OpenSSH_7.9p1")
        self.assertEqual(findings[0]["raw"]["address"], {"address": "192.0.2.10", "family": "ipv4"})

    def test_closed_port_is_an_empty_success(self):
        def refused(h, p, t):
            raise ConnectionRefusedError(111, "refused")
        code, findings, body = execute("ssh-banner-scanner", lambda run: self.mod.scan(run, self.opts, connect=refused))
        self.assertEqual((code, findings, body["outcome"]), (0, [], "succeeded"))

    def test_unresolvable_is_a_failed_run(self):
        def gai(h, p, t):
            raise socket.gaierror(-2, "unknown")
        code, _f, body = execute("ssh-banner-scanner", lambda run: self.mod.scan(run, self.opts, connect=gai))
        self.assertEqual((code, body["outcome"]), (1, "failed"))


class WhoisScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("whois-scanner")
        self.now = datetime(2026, 10, 24, tzinfo=timezone.utc)

    def record(self, days):
        return {"registrar": "R", "creation_date": "1995-08-14 04:00:00",
                "expiration_date": "x", "expiration": self.now + timedelta(days=days),
                "name_servers": ["a.iana-servers.net"]}

    def test_classify(self):
        self.assertEqual([f[0] for f in self.mod.classify(self.record(200), self.now)], ["SAMMA-WHOIS-RECORD"])
        self.assertEqual([f[0] for f in self.mod.classify(self.record(20), self.now)],
                         ["SAMMA-WHOIS-DOMAIN-EXPIRING", "SAMMA-WHOIS-RECORD"])
        self.assertEqual([f[0] for f in self.mod.classify(self.record(-1), self.now)],
                         ["SAMMA-WHOIS-DOMAIN-EXPIRED", "SAMMA-WHOIS-RECORD"])

    def test_scan(self):
        _c, findings, _b = execute("whois-scanner", lambda run: self.mod.scan(run, lookup=lambda t: self.record(400)))
        self.assertEqual(findings[0]["endpoint"]["scheme"], "whois")
        self.assertEqual(findings[0]["raw"]["name_servers"], ["a.iana-servers.net"])
        self.assertNotIn("expiration", findings[0]["raw"], "the datetime stays out of raw")

    def test_lookup_error_fails_the_run(self):
        def boom(t):
            raise RuntimeError("whois server refused")
        code, _f, body = execute("whois-scanner", lambda run: self.mod.scan(run, lookup=boom))
        self.assertEqual((code, body["outcome"], body["message"]), (1, "failed", "RuntimeError: whois server refused"))

    def test_date_helpers(self):
        when = datetime(2027, 1, 1)
        self.assertEqual(self.mod.as_datetime([when]).tzinfo, timezone.utc)
        self.assertIsNone(self.mod.as_datetime("2027-01-01"))
        self.assertEqual(self.mod.as_text(["a", "b"]), "a")


class TracerouteScannerTest(unittest.TestCase):
    SAMPLE = ("traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n"
              " 1  10.0.0.1  1.234 ms\n"
              " 2  *\n"
              " 3  93.184.216.34  12.5 ms\n")

    def setUp(self):
        self.mod = load_scanner("traceroute-scanner")

    def test_parse(self):
        hops = self.mod.parse(self.SAMPLE)
        self.assertEqual([h["ip"] for h in hops], ["10.0.0.1", None, "93.184.216.34"])

    def test_scan(self):
        class Result(object):
            returncode = 0
            stdout = self.SAMPLE
            stderr = ""
        calls = []

        def runner(cmd, **kwargs):
            calls.append(cmd)
            return Result()
        opts = {"max_hops": 15, "timeout": 2}
        _c, findings, _b = execute("traceroute-scanner", lambda run: self.mod.scan(run, opts, runner=runner))
        self.assertEqual(calls[0], ["traceroute", "-n", "-q", "1", "-w", "2", "-m", "15", "example.com"])
        self.assertEqual(ids(findings), ["SAMMA-TRACEROUTE-PATH"])
        self.assertTrue(findings[0]["raw"]["reached"])
        self.assertIn("2 *", findings[0]["evidence"])

    def test_no_hops_fails_the_run(self):
        class Result(object):
            returncode = 2
            stdout = ""
            stderr = "traceroute: unknown host\n"
        code, _f, body = execute("traceroute-scanner",
                                 lambda run: self.mod.scan(run, {"max_hops": 3, "timeout": 1}, runner=lambda c, **k: Result()))
        self.assertEqual((code, body["outcome"]), (1, "failed"))
        self.assertIn("unknown host", body["message"])


class WafScannerTest(unittest.TestCase):
    def setUp(self):
        self.mod = load_scanner("waf-scanner")
        self.opts = {"https": True, "port": 443, "timeout": 1, "user_agent": "t"}

    def test_fingerprint_cloudflare(self):
        name, strong, indicators = self.mod.fingerprint(
            {"cf-ray": "abc", "server": "cloudflare"}, ["__cf_bm=xyz; Path=/"], "")
        self.assertEqual((name, strong), ("Cloudflare", True))
        self.assertEqual(len(indicators), 3)

    def test_detected_evidence_names_indicators_without_values(self):
        def fetch_(target, opts, path):
            if path == "/":
                return 200, [("CF-RAY", "secret-ray-id"), ("Set-Cookie", "__cf_bm=tokenvalue; Path=/")], "<html>"
            return 403, [], "blocked"
        _c, findings, _b = execute("waf-scanner", lambda run: self.mod.scan(run, self.opts, fetch_=fetch_))
        self.assertEqual(ids(findings), ["SAMMA-WAF-DETECTED"])
        evidence = findings[0]["evidence"]
        self.assertIn("Cloudflare (confidence confirmed)", evidence)
        self.assertIn("header cf-ray", evidence)
        self.assertIn("3 of 3 probes blocked", evidence)
        self.assertNotIn("secret-ray-id", evidence)
        self.assertNotIn("tokenvalue", evidence)
        self.assertNotIn("<html>", str(findings[0]["raw"]))
        self.assertEqual(findings[0]["raw"]["waf_confidence"], "confirmed")

    def test_not_detected(self):
        _c, findings, _b = execute("waf-scanner",
                                   lambda run: self.mod.scan(run, self.opts, fetch_=lambda t, o, p: (200, [("Server", "nginx")], "ok")))
        self.assertEqual(ids(findings), ["SAMMA-WAF-NOT-DETECTED"])
        self.assertEqual(findings[0]["severity"], "LOW")
        self.assertIn("0 of 3 probes blocked", findings[0]["evidence"])

    def test_baseline_failure_fails_the_run(self):
        def fetch_(t, o, p):
            raise ConnectionResetError("reset")
        code, _f, body = execute("waf-scanner", lambda run: self.mod.scan(run, self.opts, fetch_=fetch_))
        self.assertEqual((code, body["outcome"]), (1, "failed"))

    def test_probe_failures_do_not_fail_the_run(self):
        def fetch_(target, opts, path):
            if path == "/":
                return 200, [], ""
            raise socket.timeout("slow")
        code, findings, _b = execute("waf-scanner", lambda run: self.mod.scan(run, self.opts, fetch_=fetch_))
        self.assertEqual(code, 0)
        self.assertEqual(findings[0]["raw"]["active_probes"][0]["error"], "TimeoutError: slow")
