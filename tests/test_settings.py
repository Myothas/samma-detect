"""Settings precedence: environment > config.yaml > built-in default, with a
port that follows its scheme (samma_finding.config.setting and endpoint)."""

import unittest

from samma_finding import config
from .helpers import execute, load_scanner
from .test_scanners import FakeOpener

HH = {"http-headers-scanner": {"port": 80, "https": False, "timeout": 5}}
WAF = {"waf-scanner": {"port": 443, "https": True, "timeout": 5, "user_agent": "cfg-agent"}}
TLS = {"tls-scanner": {"port": 8443, "timeout": 9, "verify_cert": False}}
HR = {"http-redirect-scanner": {"https": False, "timeout": 5, "max_redirects": 10}}


class SettingTest(unittest.TestCase):
    def test_environment_then_file_then_default(self):
        self.assertEqual(config.setting({"TIMEOUT": "7"}, {"timeout": 3}, "timeout", 5), "7")
        self.assertEqual(config.setting({}, {"timeout": 3}, "timeout", 5), 3)
        self.assertEqual(config.setting({}, {}, "timeout", 5), 5)

    def test_blank_variable_and_null_key_count_as_unset(self):
        self.assertEqual(config.setting({"TIMEOUT": "  "}, {"timeout": 3}, "timeout", 5), 3)
        self.assertEqual(config.setting({"TIMEOUT": ""}, {}, "timeout", 5), 5)
        self.assertEqual(config.setting({}, {"timeout": None}, "timeout", 5), 5)

    def test_env_key_is_the_upper_cased_key_unless_given(self):
        self.assertEqual(config.setting({"MAX_REDIRECTS": "2"}, {}, "max_redirects", 10), "2")
        self.assertEqual(config.setting({"HOPS": "4"}, {}, "max_redirects", 10, env_key="HOPS"), "4")


class EndpointTest(unittest.TestCase):
    """The http-headers-scanner section of config.yaml: port 80, https false."""

    section = {"port": 80, "https": False}

    def test_https_from_the_environment_without_port_means_443(self):
        # The soak finding: HTTPS=True alone used to inherit port 80 from
        # config.yaml and speak TLS to it.
        self.assertEqual(config.endpoint({"HTTPS": "True"}, self.section), (True, 443))

    def test_environment_port_wins(self):
        self.assertEqual(config.endpoint({"HTTPS": "True", "PORT": "8443"}, self.section), (True, 8443))
        self.assertEqual(config.endpoint({"PORT": "8080"}, self.section), (False, 8080))

    def test_file_only(self):
        self.assertEqual(config.endpoint({}, self.section), (False, 80))
        self.assertEqual(config.endpoint({}, {"port": 8443, "https": True}), (True, 8443))

    def test_neither_follows_the_default_scheme(self):
        self.assertEqual(config.endpoint({}, {}), (False, 80))
        self.assertEqual(config.endpoint({}, {}, default_https=True), (True, 443))

    def test_file_port_without_a_scheme_is_honoured_under_either_scheme(self):
        self.assertEqual(config.endpoint({"HTTPS": "true"}, {"port": 8443}), (True, 8443))
        self.assertEqual(config.endpoint({}, {"port": 8080}), (False, 8080))

    def test_plain_http_from_the_environment_does_not_reuse_the_files_tls_port(self):
        self.assertEqual(config.endpoint({"HTTPS": "false"}, {"port": 443, "https": True}, default_https=True), (False, 80))

    def test_blank_port_counts_as_unset(self):
        self.assertEqual(config.endpoint({"HTTPS": "yes", "PORT": ""}, self.section), (True, 443))


class ScannerSettingsTest(unittest.TestCase):
    def test_http_headers_as_the_operator_runs_it(self):
        mod = load_scanner("http-headers-scanner")
        opts = mod.settings({"HTTPS": "True"}, cfg=HH)
        self.assertEqual((opts["https"], opts["port"], opts["timeout"]), (True, 443, 5.0))
        self.assertEqual(mod.settings({}, cfg=HH)["port"], 80)
        self.assertEqual(mod.settings({}, cfg={})["port"], 80)
        opts = mod.settings({"HTTPS": "True", "PORT": "8443", "TIMEOUT": "2"}, cfg=HH)
        self.assertEqual((opts["port"], opts["timeout"]), (8443, 2.0))

    def test_waf(self):
        mod = load_scanner("waf-scanner")
        self.assertEqual(mod.settings({}, cfg={})["port"], 443)
        opts = mod.settings({"HTTPS": "false"}, cfg=WAF)
        self.assertEqual((opts["https"], opts["port"], opts["user_agent"]), (False, 80, "cfg-agent"))
        self.assertEqual(mod.settings({"USER_AGENT": "x"}, cfg=WAF)["user_agent"], "x")

    def test_tls(self):
        mod = load_scanner("tls-scanner")
        self.assertEqual(mod.settings({"PORT": "9443"}, cfg=TLS)["port"], 9443)
        opts = mod.settings({}, cfg=TLS)
        self.assertEqual((opts["port"], opts["timeout"], opts["verify_cert"]), (8443, 9.0, False))
        self.assertEqual(mod.settings({}, cfg={})["port"], 443)

    def test_http_redirect_start_scheme_is_explicit(self):
        mod = load_scanner("http-redirect-scanner")
        opts = mod.settings({}, cfg=HR)
        self.assertEqual((opts["https"], opts["port"], opts["max_redirects"]), (False, 80, 10))
        self.assertEqual(mod.to_url("example.com", opts), "http://example.com")
        opts = mod.settings({"HTTPS": "true"}, cfg=HR)
        self.assertEqual((opts["https"], opts["port"]), (True, 443))
        self.assertEqual(mod.to_url("example.com", opts), "https://example.com")
        self.assertEqual(mod.to_url("example.com", {"https": True, "port": 8443}), "https://example.com:8443")
        self.assertEqual(mod.to_url("2001:db8::1", {"https": False, "port": 8080}), "http://[2001:db8::1]:8080")
        self.assertEqual(mod.to_url("https://example.com/x", {"https": False, "port": 80}), "https://example.com/x")

    def test_http_redirect_scan_starts_where_the_settings_say(self):
        mod = load_scanner("http-redirect-scanner")
        opts = {"https": True, "port": 443, "timeout": 1, "max_redirects": 4}
        code, findings, _body = execute(
            "http-redirect-scanner",
            lambda run: mod.scan(run, opts, opener=FakeOpener({"https://example.com": 200})))
        self.assertEqual(code, 0)
        self.assertTrue(findings)
        self.assertEqual(findings[0]["endpoint"], {"host": "example.com", "port": 443, "scheme": "https"})
