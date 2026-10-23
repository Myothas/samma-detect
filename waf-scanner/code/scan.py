"""waf-scanner: is a web application firewall or CDN in front of the target.

Passive fingerprints (headers and cookies of ``GET /``) plus three probe
requests with common injection payloads. The verdict is one finding either
way; evidence names the indicators, header and cookie values stay under
``raw`` and no response body is ever recorded.
"""

import http.client
import os
import urllib.parse

import samma_finding
from samma_finding import config
from samma_finding.run import describe_exception

SCANNER = "waf-scanner"
CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "config.yaml")

# Vendor signature table. Each rule:
#   source: 'header' | 'cookie' | 'body'
#   name:   header/cookie name (case-insensitive), ignored for body
#   match:  None (presence only), or a substring to match (case-insensitive)
#   strength: 'strong' for vendor-specific, 'weak' for generic
WAF_SIGNATURES = [
    ('Cloudflare', [
        {'source': 'header', 'name': 'cf-ray',     'match': None,         'strength': 'strong'},
        {'source': 'header', 'name': 'cf-cache-status', 'match': None,    'strength': 'strong'},
        {'source': 'header', 'name': 'server',     'match': 'cloudflare', 'strength': 'strong'},
        {'source': 'cookie', 'name': '__cf_bm',    'match': None,         'strength': 'strong'},
        {'source': 'cookie', 'name': '__cfduid',   'match': None,         'strength': 'strong'},
    ]),
    ('Sucuri', [
        {'source': 'header', 'name': 'x-sucuri-id',    'match': None, 'strength': 'strong'},
        {'source': 'header', 'name': 'x-sucuri-cache', 'match': None, 'strength': 'strong'},
    ]),
    ('Akamai', [
        {'source': 'header', 'name': 'server',                'match': 'akamaighost', 'strength': 'strong'},
        {'source': 'header', 'name': 'x-akamai-transformed',  'match': None,          'strength': 'strong'},
        {'source': 'cookie', 'name': 'ak_bmsc',               'match': None,          'strength': 'strong'},
    ]),
    ('AWS CloudFront', [
        {'source': 'header', 'name': 'x-amz-cf-id',  'match': None,       'strength': 'strong'},
        {'source': 'header', 'name': 'server',       'match': 'cloudfront', 'strength': 'strong'},
        {'source': 'header', 'name': 'via',          'match': 'cloudfront', 'strength': 'strong'},
    ]),
    ('F5 BIG-IP ASM', [
        {'source': 'header', 'name': 'server',   'match': 'bigip',         'strength': 'strong'},
        {'source': 'cookie', 'name': 'ts0',      'match': None,            'strength': 'weak'},
        {'source': 'cookie', 'name': 'bigipserver', 'match': None,         'strength': 'strong'},
    ]),
    ('Imperva Incapsula', [
        {'source': 'header', 'name': 'x-iinfo',         'match': None, 'strength': 'strong'},
        {'source': 'cookie', 'name': 'incap_ses_',      'match': None, 'strength': 'strong'},
        {'source': 'cookie', 'name': 'visid_incap_',    'match': None, 'strength': 'strong'},
    ]),
    ('Barracuda', [
        {'source': 'cookie', 'name': 'barra_counter_session', 'match': None, 'strength': 'strong'},
    ]),
    ('Fastly', [
        {'source': 'header', 'name': 'server',              'match': 'fastly', 'strength': 'strong'},
        {'source': 'header', 'name': 'x-fastly-request-id', 'match': None,     'strength': 'strong'},
    ]),
    ('Azure Front Door', [
        {'source': 'header', 'name': 'x-azure-ref', 'match': None, 'strength': 'strong'},
    ]),
    ('ModSecurity', [
        {'source': 'header', 'name': 'server', 'match': 'mod_security', 'strength': 'strong'},
        {'source': 'header', 'name': 'server', 'match': 'noyb',         'strength': 'strong'},
    ]),
    ('Wallarm', [
        {'source': 'header', 'name': 'nginx-wallarm', 'match': None, 'strength': 'strong'},
    ]),
    ('Generic WAF', [
        {'source': 'header', 'name': 'server',           'match': 'firewall', 'strength': 'weak'},
        {'source': 'header', 'name': 'x-waf-status',     'match': None,       'strength': 'weak'},
        {'source': 'header', 'name': 'x-firewall',       'match': None,       'strength': 'weak'},
    ]),
]

# Active probes, sent as URL-encoded query strings on GET /
ACTIVE_PROBES = [
    ('sqli',      "id=1' OR '1'='1--"),
    ('xss',       "q=<script>alert(1)</script>"),
    ('traversal', "file=../../../../etc/passwd"),
]

BLOCKED_STATUSES = {403, 406, 419, 429, 451, 501, 503}
BLOCKED_BODY_MARKERS = [
    'blocked', 'firewall', 'security', 'forbidden',
    'incident id', 'ray id', 'attack', 'denied',
]


def settings(environ=None, cfg=None):
    env = os.environ if environ is None else environ
    section = config.section("waf-scanner", CONFIG_PATH, cfg)
    https = config.truthy(env.get("HTTPS", section.get("https", True)))
    default_port = 443 if https else 80
    return {
        "https": https,
        "port": int(env.get("PORT", section.get("port", default_port))),
        "timeout": float(env.get("TIMEOUT", section.get("timeout", 5))),
        "user_agent": env.get("USER_AGENT", section.get("user_agent", "samma-io-waf-scanner/1.0")),
    }


def fetch(target, opts, path):
    """``(status, [(header, value)], body_text)``; the body never leaves this module."""
    if opts["https"]:
        conn = http.client.HTTPSConnection(target, opts["port"], timeout=opts["timeout"])
    else:
        conn = http.client.HTTPConnection(target, opts["port"], timeout=opts["timeout"])
    try:
        conn.request('GET', path, headers={'User-Agent': opts["user_agent"], 'Accept': '*/*'})
        resp = conn.getresponse()
        status = resp.status
        raw_headers = resp.getheaders()
        body = resp.read(4096)
        try:
            body_text = body.decode('utf-8', errors='replace')
        except Exception:
            body_text = ''
        return status, raw_headers, body_text
    finally:
        conn.close()


def _collect_cookies(raw_headers):
    return [v for k, v in raw_headers if k.lower() == 'set-cookie']


def _match_indicator(rule, headers_lower, cookies, body_lower):
    name = rule['name']
    match = rule['match']
    src = rule['source']

    if src == 'header':
        if name not in headers_lower:
            return None
        value = headers_lower[name]
        if match is None or match.lower() in value.lower():
            return {'source': 'header', 'name': name, 'value': value}
        return None

    if src == 'cookie':
        for c in cookies:
            cookie_name = c.split('=', 1)[0].strip().lower()
            if name.lower() in cookie_name:
                return {'source': 'cookie', 'name': name, 'value': c.split(';', 1)[0]}
        return None

    if src == 'body':
        if match and match.lower() in body_lower:
            return {'source': 'body', 'name': name, 'value': match}
        return None

    return None


def _probe_blocked(status, body_lower, baseline_status):
    if status in BLOCKED_STATUSES and 200 <= baseline_status < 300:
        return True
    if status != baseline_status and status >= 400 and 200 <= baseline_status < 300:
        return True
    for marker in BLOCKED_BODY_MARKERS:
        if marker in body_lower:
            return True
    return False


def fingerprint(headers_lower, cookies, body_lower):
    """``(waf_name, has_strong_match, passive_indicators)`` from one response."""
    vendor_matches = []
    for vendor, rules in WAF_SIGNATURES:
        matched = []
        has_strong = False
        for rule in rules:
            ind = _match_indicator(rule, headers_lower, cookies, body_lower)
            if ind:
                ind['vendor'] = vendor
                matched.append(ind)
                if rule['strength'] == 'strong':
                    has_strong = True
        if matched:
            vendor_matches.append((vendor, matched, has_strong))

    passive_indicators = []
    waf_name = None
    has_strong_match = False
    if vendor_matches:
        # Pick vendor with most matches; ties resolve by table order (first wins)
        vendor_matches.sort(key=lambda x: -len(x[1]))
        best_vendor, _best_matches, best_strong = vendor_matches[0]
        if best_vendor != 'Generic WAF':
            waf_name = best_vendor
        has_strong_match = best_strong
        for _, matches, _ in vendor_matches:
            passive_indicators.extend(matches)
    return waf_name, has_strong_match, passive_indicators


def resolve_confidence(any_probe_blocked, has_strong_match, passive_indicators):
    if any_probe_blocked:
        return 'confirmed', True
    if has_strong_match:
        return 'high', True
    if len(passive_indicators) >= 2:
        return 'medium', True
    if len(passive_indicators) == 1:
        return 'low', True
    return 'none', False


def detect(target, opts, fetch_=fetch):
    """The v1 result dictionary; the baseline request's errors propagate."""
    baseline_status, baseline_headers, baseline_body = fetch_(target, opts, '/')
    headers_lower = {k.lower(): v for k, v in baseline_headers}
    cookies = _collect_cookies(baseline_headers)
    waf_name, has_strong_match, passive_indicators = fingerprint(
        headers_lower, cookies, baseline_body.lower())

    active_probes = []
    any_probe_blocked = False
    for probe_name, query in ACTIVE_PROBES:
        path = '/?' + urllib.parse.quote(query, safe='=&')
        try:
            p_status, _p_headers, p_body = fetch_(target, opts, path)
            blocked = _probe_blocked(p_status, p_body.lower(), baseline_status)
        except Exception as exc:
            active_probes.append({'payload': probe_name, 'error': describe_exception(exc),
                                  'blocked': False})
            continue
        if blocked:
            any_probe_blocked = True
        active_probes.append({'payload': probe_name, 'status_code': p_status, 'blocked': blocked})

    confidence, waf_detected = resolve_confidence(any_probe_blocked, has_strong_match,
                                                  passive_indicators)
    return {
        'waf_detected': waf_detected,
        'waf_name': waf_name,
        'waf_confidence': confidence,
        'passive_indicators': passive_indicators,
        'active_probes': active_probes,
        'baseline_status': baseline_status,
    }


def classify(result):
    """``[(check_id, evidence)]``; indicator names only, never values."""
    probes = result.get('active_probes') or []
    blocked = sum(1 for p in probes if p.get('blocked'))
    indicators = ", ".join("%s %s" % (i['source'], i['name'])
                           for i in result.get('passive_indicators') or []) or "none"
    probe_text = "%d of %d probes blocked (baseline status %s)" % (
        blocked, len(probes), result.get('baseline_status'))
    if result.get('waf_detected'):
        return [("SAMMA-WAF-DETECTED", "%s (confidence %s); indicators: %s; %s" % (
            result.get('waf_name') or "unidentified vendor", result.get('waf_confidence'),
            indicators, probe_text))]
    return [("SAMMA-WAF-NOT-DETECTED", "no vendor indicators in headers or cookies; %s" % probe_text)]


def scan(run, opts=None, fetch_=fetch):
    opts = opts or settings()
    result = detect(run.target, opts, fetch_)
    raw = {'host': run.target, 'port': opts["port"], 'https': opts["https"], 'type': 'WAFDetection'}
    raw.update(result)
    endpoint = run.endpoint(port=opts["port"], scheme="https" if opts["https"] else "http")
    for check_id, evidence in classify(result):
        run.finding(check_id, endpoint, evidence=evidence, raw=raw)


if __name__ == "__main__":
    samma_finding.main(SCANNER, scan)
