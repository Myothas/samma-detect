# detect: the Samma detect scanners

Nine small, open-source security scanners. Each one checks one thing about a host, reports one
message per finding with a stable check id and a severity, says how the run ended, and exits. They are the light, always-on layer of
[Samma](https://github.com/samma-io/guide): the Samma operator runs them in your Kubernetes cluster
against every Ingress you annotate, and the findings end up in Grafana in that same cluster.

Images are published to `ghcr.io/samma-io/detect-<tool-name>:latest` on every push to `main`.

---

## The scanners and what they are for

| Scanner | What it checks | Use it for |
|---|---|---|
| `tls-scanner` | Certificate validity, expiry and days left, issuer, protocol, cipher | Catching expiring or invalid certificates and old TLS versions |
| `http-headers-scanner` | Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection | OWASP secure-headers hygiene on every web endpoint |
| `http-redirect-scanner` | Full redirect chain, hop by hop | Making sure HTTP goes to HTTPS and nothing redirects somewhere unexpected |
| `port-scanner` | Open TCP ports (default 80, 443, 8080, 8443) | Spotting services that should not be exposed |
| `ssh-banner-scanner` | SSH banner and software version | Finding outdated SSH servers |
| `dns-scanner` | A, AAAA, MX and TXT records | Tracking DNS changes and dangling records |
| `whois-scanner` | Registrar, creation and expiry dates, name servers | Domain expiry and ownership changes |
| `traceroute-scanner` | Network path, hop by hop | Seeing how a target is reached, and when that changes |
| `waf-scanner` | WAF or CDN fingerprints and three probe requests | Knowing which edge protection fronts a host, if any |

None of them sends attack-like traffic, so they are safe to run often. For deeper checks, the
operator also runs the classic scanners: [nmap](https://github.com/samma-io/nmap),
[nikto](https://github.com/samma-io/nikto) and [tsunami](https://github.com/samma-io/tsunami).
With a [samma.io](https://samma.io) connection you also get external scanners and validated vendor
scanners, such as PCI DSS ASV, for tagged Ingresses. The
[guide](https://github.com/samma-io/guide/blob/main/1a-the-scanners/README.md) covers the whole
picture.

---

## How it works

Every tool follows the same pattern:

1. Read configuration from environment variables (or fall back to `config.yaml` defaults).
2. Run the detection and emit one **finding** message per failing check (or per inventory fact)
   through the shared `samma_finding` package in `common/`. Every message is printed to stdout
   as one JSON line and, when `NATS_ENABLED=true`, published to NATS.
3. End the run with exactly one **run** message that says whether the scan `succeeded`,
   `failed` (an exception) or `timed_out` (SIGTERM from a Job deadline).
4. Optionally append every message to `/out/<tool-name>.json` when `WRITE_TO_FILE=true`, and
   write `/out/die` when finished, so a sidecar (if any) knows the scan is done.

The message shapes are in [Finding schema v2](#finding-schema-v2) below. Under the Samma
operator, findings go **scanner → NATS (`samma-io.scan`) → bridge → TimescaleDB → Grafana**.
You don't run anything else.

---

## Quick start

All `docker compose` commands use the repo root as build context, so always run them from the **repo root**.

### Pull and run a pre-built image

```bash
TARGET=example.com docker compose -f tls-scanner/docker-compose.yaml up
```

### Build and run locally

```bash
# Port scan
TARGET=scanme.nmap.org docker compose -f port-scanner/docker-compose.yaml up --build

# Traceroute
TARGET=scanme.nmap.org docker compose -f traceroute-scanner/docker-compose.yaml up --build

# TLS certificate check
TARGET=example.com docker compose -f tls-scanner/docker-compose.yaml up --build

# HTTP security headers
TARGET=example.com docker compose -f http-headers-scanner/docker-compose.yaml up --build

# DNS records
TARGET=example.com docker compose -f dns-scanner/docker-compose.yaml up --build

# SSH banner
TARGET=scanme.nmap.org docker compose -f ssh-banner-scanner/docker-compose.yaml up --build

# WHOIS
TARGET=example.com docker compose -f whois-scanner/docker-compose.yaml up --build

# HTTP redirect chain
TARGET=http://example.com docker compose -f http-redirect-scanner/docker-compose.yaml up --build
```

### Read the output

Each tool writes one JSON message per line to `<tool-name>/out/<tool-name>.json`; the last
line is the run message:

```bash
cat port-scanner/out/port-scanner.json
cat tls-scanner/out/tls-scanner.json
# etc.
```

Completion is signalled by the `die` file:

```bash
ls port-scanner/out/die   # exists when the scan is done
```

---

## Environment variables

Every tool accepts a common set of variables plus tool-specific ones.

### Common variables (all tools)

| Variable | Default | Description |
|---|---|---|
| `TARGET` | **required** | Host or IP to scan |
| `WRITE_TO_FILE` | `False` | Set to `true` to write JSON to `/out/` |
| `PARSER` | `<tool-name>` | Output filename (without `.json`) |
| `SAMMA_IO_SCANNER` | `<tool-name>` | Tool label added to every record |
| `SAMMA_IO_ID` | `1234` | Deployment ID added to every record |
| `SAMMA_IO_TAGS` | `['scanner']` | Tags added to every record |
| `SAMMA_IO_JSON` | `{}` | Extra arbitrary JSON added to every record |
| `TARGET_ID` | — | samma.io target id, so results show on that target in the dashboard |
| `NATS_ENABLED` | `False` | Set to `true` to publish every finding to NATS |
| `NATS_URL` | `nats://localhost:4222` | NATS server |
| `NATS_SUBJECT` | `samma-io.scan` | Subject to publish on |
| `SAMMA_RUN_ID` | the hostname (the Job's pod name) | `runId` on every message of this run |
| `SAMMA_SCANNER_VERSION` | the `VERSION` file | `scannerVersion` on every message |
| `OUT_DIR` | `/out` | Where the file output and the `die` marker go |

### port-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | — | Scan a single port |
| `PORTS` | `80,443,8080,8443` | Comma-separated list of ports |
| `TIMEOUT` | `3` | Connection timeout (seconds) |

```bash
TARGET=scanme.nmap.org PORTS=22,80,443 docker compose -f port-scanner/docker-compose.yaml up
```

### traceroute-scanner

| Variable | Default | Description |
|---|---|---|
| `MAX_HOPS` | `30` | Maximum TTL / hop count |
| `TIMEOUT` | `2` | Per-probe wait time (seconds) |

```bash
TARGET=8.8.8.8 MAX_HOPS=15 docker compose -f traceroute-scanner/docker-compose.yaml up
```

### tls-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | `443` | TLS port |
| `TIMEOUT` | `5` | Connection timeout (seconds) |
| `VERIFY_CERT` | `True` | Validate certificate chain |

```bash
TARGET=example.com VERIFY_CERT=False docker compose -f tls-scanner/docker-compose.yaml up
```

### http-headers-scanner

| Variable | Default | Description |
|---|---|---|
| `HTTPS` | `False` | Use HTTPS instead of HTTP |
| `PORT` | `80` | Port to connect to |
| `TIMEOUT` | `5` | Connection timeout (seconds) |

```bash
TARGET=example.com HTTPS=True PORT=443 docker compose -f http-headers-scanner/docker-compose.yaml up
```

Checked headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`.

### dns-scanner

| Variable | Default | Description |
|---|---|---|
| `RECORD_TYPES` | `A,AAAA,MX,TXT` | Comma-separated record types to query |

```bash
TARGET=example.com RECORD_TYPES=A,MX,TXT docker compose -f dns-scanner/docker-compose.yaml up
```

### ssh-banner-scanner

| Variable | Default | Description |
|---|---|---|
| `PORT` | `22` | SSH port |
| `TIMEOUT` | `5` | Connection timeout (seconds) |

```bash
TARGET=scanme.nmap.org PORT=2222 docker compose -f ssh-banner-scanner/docker-compose.yaml up
```

### whois-scanner

| Variable | Default | Description |
|---|---|---|
| *(none beyond common)* | | |

```bash
TARGET=example.com docker compose -f whois-scanner/docker-compose.yaml up
```

### http-redirect-scanner

| Variable | Default | Description |
|---|---|---|
| `TIMEOUT` | `5` | Per-request timeout (seconds) |
| `MAX_REDIRECTS` | `10` | Maximum hops to follow |

```bash
TARGET=http://example.com MAX_REDIRECTS=5 docker compose -f http-redirect-scanner/docker-compose.yaml up
```

---

## Finding schema v2

Every message a scanner emits, on NATS and in the file output, is one JSON document with the
same envelope:

| Field | Meaning |
|---|---|
| `schema` | Always `samma.io/scan/v2` |
| `kind` | `finding` or `run` |
| `scanner` | The tool name, for example `tls-scanner` |
| `scannerVersion` | `SAMMA_SCANNER_VERSION`, else the `VERSION` file baked into the image |
| `target` | The `TARGET` the scanner was given, verbatim |
| `runId` | `SAMMA_RUN_ID`, else the hostname, which under Kubernetes is the Job's pod name |
| `emittedAt` | RFC 3339 UTC time the message was built |
| `samma-io` | The legacy block `{scanner, id, tags, json}`, unchanged from v1 |

### A finding

One finding is one failing check on one endpoint, or one INFO inventory fact (an open port, an
observed certificate). It adds:

| Field | Meaning |
|---|---|
| `checkId` | Stable id, namespaced per scanner, for example `SAMMA-TLS-PROTOCOL-DEPRECATED`. Never renamed: a renamed check is a new check |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `INFO` |
| `title` | One line, the same for every endpoint where the check fails |
| `endpoint` | `{host, port, scheme}`; `host` is the name the scanner was given, `port` may be `null` |
| `evidence` | What was seen, at most 1 KiB, never a response body |
| `remediation` | What to change |
| `references` | Links, may be empty |
| `cveIds` | CVE ids when a scanner identifies one; empty today |
| `compliance` | Reserved for framework mappings; empty today |
| `raw` | The scanner's own record, the fields the v1 output had (`host`, `port`, `type`, ...) plus the resolved address where that matters |

`host`, `port`, `status` and `type` from `raw` are also mirrored at the top level, because the
current bridge reads them there. New consumers should read `raw`.

```json
{
  "schema": "samma.io/scan/v2",
  "kind": "finding",
  "scanner": "tls-scanner",
  "scannerVersion": "2.0.0",
  "target": "api.example.com",
  "runId": "tls-scanner-api-example-com-28934712-k9z2p",
  "emittedAt": "2026-10-24T02:00:21Z",
  "checkId": "SAMMA-TLS-PROTOCOL-DEPRECATED",
  "severity": "HIGH",
  "title": "Deprecated TLS protocol version negotiated",
  "endpoint": {"host": "api.example.com", "port": 443, "scheme": "https"},
  "evidence": "negotiated TLSv1",
  "remediation": "Disable SSLv3, TLS 1.0 and TLS 1.1 in the ingress controller or server TLS options and allow TLS 1.2 and 1.3 only.",
  "references": ["https://datatracker.ietf.org/doc/html/rfc8996"],
  "cveIds": [],
  "compliance": [],
  "raw": {"host": "api.example.com", "port": 443, "protocol": "TLSv1", "cipher": "AES128-SHA", "valid": true, "type": "TLSScan", "address": {"address": "192.0.2.10", "family": "ipv4"}},
  "host": "api.example.com",
  "port": 443,
  "type": "TLSScan",
  "samma-io": {"scanner": "tls-scanner", "id": "1234", "tags": ["scanner"], "json": "{}"}
}
```

### The run message

Sent exactly once, last, whatever happened. It adds:

| Field | Meaning |
|---|---|
| `outcome` | `succeeded`, `failed` or `timed_out` |
| `message` | Empty on success; on failure the exception class and its short message, never a stack trace; on timeout `SIGTERM received` |
| `startedAt`, `finishedAt` | RFC 3339 UTC |
| `findingCount` | Findings emitted in this run, including the ones before a crash |
| `scan` | Always `"done"`, the v1 end marker |

```json
{
  "schema": "samma.io/scan/v2",
  "kind": "run",
  "scanner": "tls-scanner",
  "scannerVersion": "2.0.0",
  "target": "api.example.com",
  "runId": "tls-scanner-api-example-com-28934712-k9z2p",
  "emittedAt": "2026-10-24T02:00:21Z",
  "outcome": "succeeded",
  "message": "",
  "startedAt": "2026-10-24T02:00:04Z",
  "finishedAt": "2026-10-24T02:00:21Z",
  "findingCount": 2,
  "scan": "done",
  "samma-io": {"scanner": "tls-scanner", "id": "1234", "tags": ["scanner"], "json": "{}"}
}
```

A consumer that keeps the last good result per target should replace it only when `outcome` is
`succeeded`; a `failed` or `timed_out` run means "we do not know", not "nothing was found". The
process exit code follows the outcome: 0, 1, or 143 for a timeout, and 2 when `TARGET` is unset.

What counts as a failed run is deliberate per scanner. A name that does not resolve fails every
scanner. `tls-scanner`, `http-headers-scanner`, `http-redirect-scanner` and `waf-scanner` fail
when the endpoint cannot be reached at all, because their one job is to judge that endpoint.
`port-scanner` and `ssh-banner-scanner` treat a refused or filtered port as an empty success,
because "nothing listens" is the answer they exist to give.

### The check catalogue

`common/samma_finding/catalog/<scanner>.py` lists every check a scanner can emit with its
severity, title, remediation and references. It is the source of truth: a scanner cannot emit a
check id that is not in its catalogue (`samma_finding` refuses it), and `tests/test_catalog.py`
checks both directions, so a new detection means a catalogue entry in the same change. Severities
are fixed per check id; when the same observation deserves different severities it is two checks
(`SAMMA-TLS-CERT-EXPIRING` and `SAMMA-TLS-CERT-EXPIRED`). Print the catalogue as JSON with
`python3 -m samma_finding.catalog` from `common/`.

| Scanner | Check id | Severity | Title |
|---|---|---|---|
| `dns-scanner` | `SAMMA-DNS-RECORDS` | INFO | DNS records observed |
| `dns-scanner` | `SAMMA-DNS-NXDOMAIN` | LOW | DNS name does not exist |
| `http-headers-scanner` | `SAMMA-HEADERS-HSTS-MISSING` | MEDIUM | Strict-Transport-Security header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-CSP-MISSING` | LOW | Content-Security-Policy header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-X-CONTENT-TYPE-OPTIONS-MISSING` | LOW | X-Content-Type-Options header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-X-FRAME-OPTIONS-MISSING` | LOW | X-Frame-Options header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-REFERRER-POLICY-MISSING` | LOW | Referrer-Policy header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-PERMISSIONS-POLICY-MISSING` | INFO | Permissions-Policy header is missing |
| `http-headers-scanner` | `SAMMA-HEADERS-X-XSS-PROTECTION-ENABLED` | INFO | Deprecated X-XSS-Protection header is enabled |
| `http-headers-scanner` | `SAMMA-HEADERS-OBSERVED` | INFO | HTTP security headers observed |
| `http-redirect-scanner` | `SAMMA-REDIRECT-HTTPS-MISSING` | MEDIUM | HTTP is not redirected to HTTPS |
| `http-redirect-scanner` | `SAMMA-REDIRECT-DOWNGRADE` | MEDIUM | Redirect chain downgrades HTTPS to HTTP |
| `http-redirect-scanner` | `SAMMA-REDIRECT-OFFSITE` | INFO | Redirect leaves the target host |
| `http-redirect-scanner` | `SAMMA-REDIRECT-TOO-MANY` | LOW | Redirect chain exceeded the hop limit |
| `http-redirect-scanner` | `SAMMA-REDIRECT-BROKEN` | LOW | Redirect target could not be reached |
| `http-redirect-scanner` | `SAMMA-REDIRECT-CHAIN` | INFO | HTTP redirect chain observed |
| `port-scanner` | `SAMMA-PORT-OPEN-ADMIN` | HIGH | Administrative or database port is reachable from the internet |
| `port-scanner` | `SAMMA-PORT-OPEN` | INFO | TCP port is open |
| `ssh-banner-scanner` | `SAMMA-SSH-PROTOCOL-V1` | HIGH | SSH protocol version 1 is offered |
| `ssh-banner-scanner` | `SAMMA-SSH-VERSION-OUTDATED` | MEDIUM | Outdated OpenSSH version in banner |
| `ssh-banner-scanner` | `SAMMA-SSH-BANNER` | INFO | SSH service banner observed |
| `tls-scanner` | `SAMMA-TLS-PROTOCOL-DEPRECATED` | HIGH | Deprecated TLS protocol version negotiated |
| `tls-scanner` | `SAMMA-TLS-CIPHER-WEAK` | MEDIUM | Weak cipher suite negotiated |
| `tls-scanner` | `SAMMA-TLS-CERT-EXPIRED` | HIGH | TLS certificate has expired |
| `tls-scanner` | `SAMMA-TLS-CERT-EXPIRING` | MEDIUM | TLS certificate expires within 14 days |
| `tls-scanner` | `SAMMA-TLS-CERT-INVALID` | HIGH | TLS certificate failed verification |
| `tls-scanner` | `SAMMA-TLS-CERTIFICATE` | INFO | TLS certificate observed |
| `traceroute-scanner` | `SAMMA-TRACEROUTE-PATH` | INFO | Network path observed |
| `waf-scanner` | `SAMMA-WAF-DETECTED` | INFO | Web application firewall or CDN detected |
| `waf-scanner` | `SAMMA-WAF-NOT-DETECTED` | LOW | No web application firewall detected |
| `whois-scanner` | `SAMMA-WHOIS-RECORD` | INFO | WHOIS record observed |
| `whois-scanner` | `SAMMA-WHOIS-DOMAIN-EXPIRING` | MEDIUM | Domain registration expires within 30 days |
| `whois-scanner` | `SAMMA-WHOIS-DOMAIN-EXPIRED` | HIGH | Domain registration has expired |

Closed ports, present headers and record types with no answer are not findings; they appear in
the evidence or `raw` of the INFO inventory finding instead.

### IPv4, IPv6 and dual-stack targets

`port-scanner` and `tls-scanner` resolve the target with `getaddrinfo` for both address
families and try every address. A port that accepts on any address is one finding, with the
per-address result under `raw.addresses`. The other scanners use the standard library's HTTP and
socket helpers, which already walk both families. `endpoint.host` is always the name the scanner
was given; the address used is under `raw`.

### Backwards compatibility

The `samma-io` block is unchanged. The v1 record of each scanner is carried in `raw`, and its
`host`, `port`, `status` and `type` are mirrored at the top level, so the current bridge's columns
keep filling. The `{"scan": "done"}` end marker is now the run message, which carries
`"scan": "done"` too. Stdout changed from Python `repr` to JSON lines. `sammaParser.py` still
exists in every tool directory as a shim over `samma_finding.legacy` for out-of-tree scanners
built on the old pattern.

---

## Configuration file

`config.yaml` at the repo root holds default values for all tools. Environment variables always take precedence.

```yaml
defaults:
  ports: [80, 443, 8080, 8443]
  timeout: 3

traceroute-scanner:
  max_hops: 30
  timeout: 2

tls-scanner:
  port: 443
  timeout: 5
  verify_cert: true

http-headers-scanner:
  port: 80
  https: false
  timeout: 5

dns-scanner:
  record_types: [A, AAAA, MX, TXT]

ssh-banner-scanner:
  port: 22
  timeout: 5

http-redirect-scanner:
  timeout: 5
  max_redirects: 10
```

---

## Tests

The shared package and every scanner's classification have standard-library unit tests, no
network and no third-party modules needed:

```bash
python3 -m unittest discover -s tests -t .
```

---

## CI/CD

Every push to `main` triggers `.github/workflows/docker-build.yml`, which builds all tool images in parallel and pushes them to the GitHub Container Registry:

```
ghcr.io/samma-io/detect-port-scanner:latest
ghcr.io/samma-io/detect-traceroute-scanner:latest
ghcr.io/samma-io/detect-tls-scanner:latest
ghcr.io/samma-io/detect-http-headers-scanner:latest
ghcr.io/samma-io/detect-dns-scanner:latest
ghcr.io/samma-io/detect-ssh-banner-scanner:latest
ghcr.io/samma-io/detect-whois-scanner:latest
ghcr.io/samma-io/detect-http-redirect-scanner:latest
ghcr.io/samma-io/detect-waf-scanner:latest
```

Each image is also tagged with the short git SHA (`sha-<7chars>`).

---

## Kubernetes

The normal way to run these in Kubernetes is the
[Samma operator](https://github.com/samma-io/operator). It creates the Jobs and CronJobs for you,
from an annotated Ingress, the API or a `Scanner` resource, and wires up NATS. For a few fixed
targets without the operator, use the Helm chart in `helm/`.

The standalone manifests below are the older way. Each tool ships `manifest/job.yaml` (one-off run) and `manifest/cron.yaml` (scheduled run). Both include the tool container and a Filebeat sidecar that ships results to Elasticsearch.

```bash
# Apply ConfigMaps + run a one-off job
kubectl apply -f port-scanner/manifest/job.yaml

# Apply ConfigMaps + schedule a recurring job
kubectl apply -f port-scanner/manifest/cron.yaml
```

The Filebeat sidecar watches for `/out/die` via a liveness probe and kills itself (and the pod) once the detection is complete.

To point tools at a different Elasticsearch cluster, set `ELASTICSEARCH_HOSTS` in the manifest:

```yaml
- name: ELASTICSEARCH_HOSTS
  value: http://my-elastic-cluster:9200
```

---

## Repo structure

```
detect/
├── VERSION                     # scannerVersion on every message
├── config.yaml
├── .github/workflows/docker-build.yml
├── common/samma_finding/       # shared: schema v2, run outcome, publishers, check catalogues
│   └── catalog/<scanner>.py
├── tests/                      # python3 -m unittest discover -s tests -t .
├── port-scanner/
├── traceroute-scanner/
├── tls-scanner/
├── http-headers-scanner/
├── dns-scanner/
├── ssh-banner-scanner/
├── whois-scanner/
├── http-redirect-scanner/
└── waf-scanner/

Each tool directory:
├── code/
│   ├── scan.py                 # detection and classification; imports samma_finding
│   ├── sammaParser.py          # compatibility shim over samma_finding.legacy
│   └── requirements.txt
├── Dockerfile                  # copies code/, common/samma_finding and VERSION
├── docker-compose.yaml
├── filebeat/
│   └── filebeat.yml
└── manifest/
    ├── job.yaml
    └── cron.yaml
```
