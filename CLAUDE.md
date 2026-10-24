# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and run

All `docker compose` commands use the **repo root as the build context** — always run them from the repo root.

```bash
# Build and run any tool (replace <tool> with the directory name)
TARGET=example.com docker compose -f <tool>/docker-compose.yaml up --build

# Run without rebuilding (uses image from GHCR)
TARGET=example.com docker compose -f <tool>/docker-compose.yaml up

# Check output
cat <tool>/out/<tool>.json

# Confirm detection finished
ls <tool>/out/die
```

Unit tests (standard library only, no network, no third-party modules) live in `tests/`:

```bash
python3 -m unittest discover -s tests -t .
```

They cover the shared package (message shape, size caps, run outcomes, IPv6 resolution) and every
scanner's classification through fakes. End-to-end verification is still manual: run the container,
inspect the JSON lines in `<tool>/out/`.

## CI/CD

`.github/workflows/docker-build.yml` runs on every push to `main`. It uses a matrix strategy to build all 9 tool images in parallel and pushes them to GHCR as `ghcr.io/samma-io/detect-<tool-name>:latest` and `ghcr.io/samma-io/detect-<tool-name>:sha-<short-sha>`.

The workflow authenticates to GHCR using the automatic `GITHUB_TOKEN`; no secrets need to be configured. `latest` is pushed only from `main` (a `workflow_dispatch` run from another branch pushes the sha tag only).

`.github/workflows/release.yaml` runs on tags `v*`: it checks that the tag equals `VERSION`, runs the unit tests, builds the nine images for linux/amd64 and linux/arm64 tagged `<version>` and `<version>-<short sha>` (never `latest`), and creates the GitHub release with every image's digest plus a `detect-<version>-images.txt` list. Releasing is: change `VERSION`, merge, push the tag. The operator chart pins these images with `scanners.detectTag`.

## Architecture

### Tool lifecycle

Each tool is a self-contained Docker image that:
1. Reads config from env vars, falling back to `config.yaml` for defaults
2. Performs the detection and calls `run.finding(check_id, endpoint, evidence=..., raw=...)` for each
   failing check or inventory fact
3. Returns from `scan(run)`; `samma_finding.main` then emits exactly one run message with the outcome
   (`succeeded`, `failed` on an exception, `timed_out` on SIGTERM) and writes `/out/die`

The `/out/die` file is the shutdown signal — the Filebeat sidecar's liveness probe watches for it and kills the pod.

### Shared package and the per-tool scan.py

- **`common/samma_finding/`** — the one output path for every tool: message schema v2 (`schema.py`),
  the run wrapper and SIGTERM handling (`run.py`), stdout/file/NATS publishers (`output.py`, the NATS
  client is imported lazily), the `config.yaml` loader (`config.py`), dual-stack resolution helpers
  (`netutil.py`) and the check catalogues (`catalog/<scanner>.py`). Every Dockerfile copies it to
  `/code/samma_finding`, next to `scan.py`, and copies `VERSION` to `/VERSION`.
- **`<tool>/code/scan.py`** — detection and classification only. It defines `settings()`, pure
  `classify(...)` helpers and `scan(run)`, and ends with `samma_finding.main(SCANNER, scan)` under
  `if __name__ == "__main__"`, so the tests can import it. Network and third-party calls are behind
  injectable arguments (`connect=`, `fetch_=`, `query=`, `runner=`) so the tests use fakes.
- **`<tool>/code/sammaParser.py`** — a shim re-exporting `samma_finding.legacy.logger`/`endThis`
  for out-of-tree scanners; nothing in this repo imports it any more.

### Check ids and severities

A check id is `SAMMA-<SCANNER>-<NAME>`, listed in `common/samma_finding/catalog/<scanner>.py` with
severity, title, remediation and references. `run.finding` refuses an id that is not in the tool's
catalogue, and `tests/test_catalog.py` fails when a scanner emits an id the catalogue lacks or the
catalogue lists an id the scanner never emits. Ids are never renamed; a renamed check is a new check.
Severity is fixed per id, so two severities for one observation means two ids.

### Config precedence

Environment variable → `config.yaml` section for that tool → hardcoded fallback in `scan.py`.

`config.yaml` lives at the repo root and is copied into every image at `/config.yaml`. `scan.py` loads it with a relative path (`../../config.yaml` from `/code/`).

### Build context

Dockerfiles `COPY` from paths relative to the repo root (`COPY port-scanner/code /code`,
`COPY common/samma_finding /code/samma_finding`, `COPY VERSION /VERSION`), which is why the build
context must be `..` in every `docker-compose.yaml` and `.` (repo root) in the GitHub Actions workflow.

### Kubernetes manifests

Each tool's `manifest/` directory contains two files with identical structure:
- `job.yaml` — one-off `batch/v1 Job`
- `cron.yaml` — `batch/v1 CronJob`

Both embed the Filebeat config and liveness script as ConfigMaps in the same file (multi-doc YAML). ConfigMap names are suffixed per tool (`-ps`, `-tr`, `-tls`, `-hh`, `-dns`, `-ssh`, `-whois`, `-hr`) to avoid collisions in the `samma-io` namespace.

## Adding a new tool

1. Create `<name>/code/scan.py` following an existing tool: `settings()`, `classify(...)`, `scan(run)`,
   and `samma_finding.main("<name>", scan)` under `if __name__ == "__main__"`; copy `sammaParser.py`
   verbatim; add `requirements.txt`
2. Add `common/samma_finding/catalog/<name_with_underscores>.py` with `PREFIX = "SAMMA-<NAME>-"` and a
   `CHECKS` dict, and register it in `catalog/__init__.py` (`SCANNERS`)
3. Add the tool to `tests/helpers.py` `SCANNERS` and a test class in `tests/test_scanners.py`
4. Create `Dockerfile` — copy the pattern from an existing tool (it already copies `common/samma_finding`
   and `VERSION`); add apt/pip deps if needed
5. Create `docker-compose.yaml` with `context: ..` and tool-specific env vars; set `image: ghcr.io/samma-io/detect-<name>:latest`
6. Copy `filebeat/filebeat.yml` verbatim from any existing tool
7. Create `manifest/job.yaml` and `manifest/cron.yaml` using a new ConfigMap suffix
8. Add a defaults section to `config.yaml`
9. Add the new tool name to the `scanner` matrix in `.github/workflows/docker-build.yml`
