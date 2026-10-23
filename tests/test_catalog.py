import json
import re
import unittest

from samma_finding import catalog, schema
from . import helpers

CHECK_ID_LITERAL = re.compile(r'"(SAMMA-[A-Z0-9-]+)"')


def emitted_ids(scanner):
    with open(helpers.scan_py(scanner), encoding="utf-8") as handle:
        return set(CHECK_ID_LITERAL.findall(handle.read()))


class CatalogueTest(unittest.TestCase):
    def test_catalogue_is_sound(self):
        self.assertEqual(catalog.validate(), [])

    def test_every_scanner_has_a_catalogue(self):
        self.assertEqual(set(catalog.SCANNERS), set(helpers.SCANNERS))

    def test_every_emitted_check_id_is_in_its_scanner_catalogue(self):
        for scanner in helpers.SCANNERS:
            ids = emitted_ids(scanner)
            self.assertTrue(ids, "%s emits no check ids" % scanner)
            catalogue = catalog.for_scanner(scanner)
            missing = ids - set(catalogue)
            self.assertEqual(missing, set(), "%s emits ids missing from its catalogue" % scanner)

    def test_every_catalogue_entry_is_emitted_by_its_scanner(self):
        for scanner in helpers.SCANNERS:
            dead = set(catalog.for_scanner(scanner)) - emitted_ids(scanner)
            self.assertEqual(dead, set(), "%s catalogue has entries the scanner never emits" % scanner)

    def test_prefixes_are_unique_and_namespaced(self):
        prefixes = [catalog.prefix_for(s) for s in helpers.SCANNERS]
        self.assertEqual(len(set(prefixes)), len(prefixes))
        for scanner in helpers.SCANNERS:
            for check_id in catalog.for_scanner(scanner):
                self.assertTrue(check_id.startswith(catalog.prefix_for(scanner)), check_id)
                self.assertTrue(schema.CHECK_ID_PATTERN.match(check_id), check_id)

    def test_severities_follow_the_agreed_rules(self):
        expected = {
            ("tls-scanner", "SAMMA-TLS-PROTOCOL-DEPRECATED"): "HIGH",
            ("tls-scanner", "SAMMA-TLS-CIPHER-WEAK"): "MEDIUM",
            ("tls-scanner", "SAMMA-TLS-CERT-EXPIRED"): "HIGH",
            ("tls-scanner", "SAMMA-TLS-CERT-INVALID"): "HIGH",
            ("http-headers-scanner", "SAMMA-HEADERS-HSTS-MISSING"): "MEDIUM",
            ("http-headers-scanner", "SAMMA-HEADERS-CSP-MISSING"): "LOW",
            ("http-headers-scanner", "SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING"): "LOW",
            ("http-redirect-scanner", "SAMMA-REDIRECT-HTTPS-MISSING"): "MEDIUM",
            ("port-scanner", "SAMMA-PORT-OPEN-ADMIN"): "HIGH",
            ("port-scanner", "SAMMA-PORT-OPEN"): "INFO",
            ("ssh-banner-scanner", "SAMMA-SSH-VERSION-OUTDATED"): "MEDIUM",
            ("dns-scanner", "SAMMA-DNS-RECORDS"): "INFO",
            ("whois-scanner", "SAMMA-WHOIS-RECORD"): "INFO",
            ("traceroute-scanner", "SAMMA-TRACEROUTE-PATH"): "INFO",
        }
        for (scanner, check_id), severity in expected.items():
            self.assertEqual(catalog.get(scanner, check_id)["severity"], severity, check_id)

    def test_admin_ports_cover_the_brief(self):
        from samma_finding.catalog import port_scanner
        for port in (22, 3389, 5432, 3306, 6379, 27017):
            self.assertIn(port, port_scanner.ADMIN_PORTS)
        for port in (80, 443, 8080, 8443):
            self.assertNotIn(port, port_scanner.ADMIN_PORTS)

    def test_catalogue_dumps_as_json(self):
        text = json.dumps(catalog.all_checks(), sort_keys=True)
        self.assertIn("SAMMA-TLS-PROTOCOL-DEPRECATED", text)

    def test_unknown_scanner(self):
        with self.assertRaises(catalog.UnknownCheck):
            catalog.for_scanner("nmap")
