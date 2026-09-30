# Iris — Cyber Security Enterprise Tool

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/Pixelcity-dev/Iris)](https://goreportcard.com/report/github.com/Pixelcity-dev/Iris)
[![Release](https://img.shields.io/github/v/release/Pixelcity-dev/Iris)](https://github.com/Pixelcity-dev/Iris/releases)
[![PixelCity](https://img.shields.io/badge/by-PixelCity-%23d4a853?labelColor=%23080707)](https://pixelcity.top)
[![Formatter](https://img.shields.io/badge/formatter-iris%20fmt-blue)](https://pixelcity.top/docs/iris#formatter)

**Cyber Security Enterprise Tool — code, supply chain, cloud, web and formatting in one binary.**

Iris unifies **SAST, SCA, Secrets, IaC, Containers, DAST, WebScan, Network, License & SBOM** for **any language** and **any webpage** — plus a zero-dependency **Formatter** (`iris fmt`). Zero dependencies, <50ms startup, compliance-ready (SOC 2, ISO 27001, GDPR, OWASP, CWE).

> **Made by [PixelCity](https://pixelcity.top) — Your Cloud, Your Rules.**
> Open source under **Apache 2.0**. Public since **v1.1.0**. Contributions welcome.

## Features — Any Language. Any Webpage. Now Formatted.

- **SAST** — 11+ langs: Go, Java, JS/TS, Python, Rust, PHP, Ruby, C/C++, C#, Kotlin, Swift • OWASP A03
- **SCA** — 11+ ecosystems: npm, pip, Maven, Go, Cargo, Composer, NuGet, RubyGems • OWASP A06
- **Secrets** — 200+ patterns (AWS, GCP, Stripe…), entropy + verified • OWASP A07
- **IaC** — Terraform, CloudFormation, Kubernetes, Dockerfile (CIS) • OWASP A05
- **Container** — Image layers, Dockerfile, distroless checks
- **DAST** — Headers, TLS, CORS, cookies, clickjacking • OWASP A01/A05
- **WebScan** — 20+ deep checks (HSTS/CSP deep, TLS cert/cipher/version, CORS wildcard, exposed `/.env/.git`, open redirect, XSS reflection, SQLi error, directory listing, `security.txt`, mixed content, SRI, HTTPS redirect) • OWASP Top 10
- **Network** — Port/service, TLS, header audit
- **License & SBOM** — SPDX/CycloneDX, license compliance
- **Any Webpage** — `iris webscan https://example.com` audits marketing sites, SaaS apps, APIs, SPAs
- **Automated Build Tests** — `iris buildtest` detects your project's language & structure (go.mod, package.json, Cargo.toml, Maven/Gradle, Python) incl. monorepos, runs the standard build + test commands, and reports compiler/test errors as findings with `file:line` and fix steps
- **Specific Fix Suggestions** — every finding gets actionable, language-aware remediation: exact commands (`sed -n` line fixes, `gofmt -w`, `npm ci`), header values (CSP/HSTS snippets incl. Caddy syntax), rotation steps for leaked secrets
- **Live Scan UI** — per-scanner spinning indicators with findings counts and durations (TTY-aware, clean output in CI)
- **PixelCity Cloud** — `iris cloud login` (Keycloak device flow via id.pixelcity.dev), plan & usage history, Pro/Enterprise checkout via payments.pixelcity.dev, dashboard at dashboard.pixelcity.dev
- **Formatter** — 7 checks, auto-fix, zero-config • `iris fmt` (`format` alias) — trailing whitespace, missing EOF newline, CRLF, mixed indentation, long lines (>120), Go `gofmt`, consecutive blanks • `<10ms` for 1000 files, no `prettier`/`black` required

## Installation

### One-Liner — CDN via Caddy

```bash
curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
# fallbacks
curl -fsSL https://cdn.pixelcity.top/iris/install.sh | sh
curl -fsSL https://pixelcity.top/iris/install.sh | sh
wget -qO- https://cdn.pixelcity.dev/iris/install.sh | sh
```

```bash
DEEPSEC_VERSION=latest curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
INSTALL_DIR=/usr/local/bin curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh -s -- --help
```

### Go Install

```bash
go install github.com/Pixelcity-dev/Iris/cmd/iris@latest
```

### Build from Source

```bash
git clone https://github.com/Pixelcity-dev/Iris.git
git clone git@github.com:Pixelcity-dev/Iris.git
cd Iris
make build
sudo make install
```

### Manual Download

```bash
# https://cdn.pixelcity.dev/iris/releases/v1.1.0/
curl -fsSL https://cdn.pixelcity.dev/iris/releases/v1.1.0/iris-linux-amd64 -o iris
chmod +x iris && sudo mv iris /usr/local/bin/
```

Releases served via `Caddy (443) → Nginx CDN (pixelcity-cdn)` from `/opt/pixelcity/cdn/assets/iris/` with `Cache-Control` & CORS.

## Quick Start

```bash
# Scan current directory
iris scan .

# Specific scanners
iris scan . --scanner sast,sca,secrets

# Formatting — check & fix
iris fmt . --check          # CI gate, exit 1 if unformatted
iris fmt . --fix            # auto-fix in place
iris scan . --scanner format --format table  # as scanner

# Deep Website Scan — 20+ checks
iris webscan https://example.com
iris webscan https://example.com --format json --output report.json
iris webscan https://example.com --severity high --format sarif --output webscan.sarif
iris scan https://example.com --scanner webscan,dast

# Severity filter
iris scan . --severity high,critical

# JSON / SARIF
iris scan . --format json --output results.json
iris scan . --format sarif --output results.sarif

# Config & DB
iris init
iris db update
```

## CLI

| Command | Description |
|---------|-------------|
| `iris scan [target]` | Scan `fs`/`url`/`image`/`repo` — auto-detects target |
| `iris webscan [url]` | Deep website audit — 20+ OWASP checks (`website`/`audit`/`wscan` aliases) |
| `iris fmt [target]` | Check & fix formatting — 7 checks, auto-fix (`format`/`style` aliases) |
| `iris buildtest [target]` | Automated build & test gate — detects toolchain, runs build + tests (`build`/`bt` aliases) |
| `iris cloud login/status/usage/upgrade` | PixelCity account: Keycloak login, plan, usage history, Pro/Enterprise checkout |
| `iris init` | Scaffold `.iris.yaml` |
| `iris db update` | Update NVD/OSV DB (air-gapped cache) |
| `iris rule list/search` | 1000+ rules, filter by `language/category/severity` |
| `iris plugin list/install` | Custom scanners, private registry |
| `iris server start` | HTTP service (`:8443`, TLS, audit log) |
| `iris mcp start` | MCP for AI agents (`iris.scan`, `iris.explain`) |
| `iris convert/generate` | Format convert, GitHub/GitLab/pre-commit generators |

Exit codes: `0` pass, `1` gate failed, `2` error. Flags: `--severity`, `--format`, `--output`, `--profile`, `--compliance`, `--fail-on`, `--no-color`.

## Formatter — `iris fmt`

Zero-dependency formatter for any language, zero config. Ideal for `pixelcity.top` style fixes and CI gates.

```bash
iris fmt . --check                # check, exit 1 if issues
iris fmt . --fix                  # fix: trailing ws, EOF newline, CRLF→LF, blank lines, gofmt
iris fmt ./web --fix              # fix specific directory
iris fmt . --diff                 # show findings without writing
iris scan . --scanner format      # use as scanner (table/json/sarif)
iris scan . --scanner format,sast # combine with security
```

**7 checks** (all `INFO`/`LOW`, category `formatting`/`style`, CWE-710):

| Rule ID | Title | Auto-fix |
|---------|-------|----------|
| `fmt-trailing-whitespace` | Trailing spaces/tabs | ✅ |
| `fmt-missing-eof-newline` | Missing newline at EOF | ✅ |
| `fmt-crlf-line-ending` | CRLF → LF | ✅ |
| `fmt-mixed-indentation` | Spaces + tabs mixed | ⚠️ suggest |
| `fmt-consecutive-blank-lines` | >1 blank lines | ✅ |
| `fmt-gofmt` | Go not `gofmt`'d (stdlib `go/format`) | ✅ |
| `fmt-line-too-long` | >120 chars | ⚠️ suggest |

**Languages:** Go, JS/TS, TSX, Python, Rust, PHP, Ruby, C/C++, C#, Kotlin, Swift, CSS, HTML, Vue, Svelte, JSON, YAML, TOML, MD, Shell, SQL, GraphQL, Dockerfile, Makefile.

**CI gate:**

```yaml
- run: iris fmt . --check   # fails if unformatted
- run: iris scan . --scanner format,sast --fail-on LOW
```

**Fix example (pixelcity-web):**

```bash
iris fmt . --fix
# Fixed src/components/sections/HeroSection.tsx
# Fixed src/app/globals.css
# Checked 127 files, fixed 3 — 0.03s
```

Alternatives: `make fmt` (`gofmt -s -w .`) remains available; `iris fmt` covers all languages in one binary.

## Configuration

```yaml
version: "1.1.0"
scanners: { sast: true, sca: true, secrets: true, iac: true, container: true, dast: true, webscan: true, network: true, license: true, format: true }
report: { format: html, color: true }   # table|json|sarif|cyclonedx|spdx|html|junit|csv
filter:
  min_severity: low          # INFO|LOW|MEDIUM|HIGH|CRITICAL
  fail_on: HIGH              # gate for CI
  compliance: [soc2, iso27001, gdpr, owasp]
  exclude_rules: [webscan-missing-security-txt, fmt-line-too-long]
```

CLI overrides: `--profile enterprise --compliance soc2 --fail-on high --severity medium`

Profiles: `enterprise` preset via `--profile` or `filter.profile`.

## Website Scanner — Deep Security Check

```bash
iris webscan https://example.com
iris webscan https://example.com --format json --output webscan.json
iris webscan https://pixelcity.top --severity medium
iris scan https://example.com --scanner webscan --format sarif
```

**20+ Checks:**
- **Security Headers Deep** - HSTS (max-age, includeSubDomains, preload), CSP (unsafe-inline, wildcard), X-Frame-Options, COOP/COEP/CORP
- **TLS Deep** - TLS version, weak ciphers, cert expiry, self-signed, hostname mismatch
- **Cookie Security** - Secure, HttpOnly, SameSite
- **CORS** - Wildcard *, reflected Origin, null
- **Information Disclosure** - Server, X-Powered-By, Via
- **HTTP Methods & TRACE** - OPTIONS, TRACE/XST
- **Clickjacking** - X-Frame-Options / CSP frame-ancestors
- **Exposed Files** - `/.env`, `/.git/HEAD`, backup.zip, config.json
- **Open Redirect** - `?url=//evil.com` (safe)
- **XSS Reflection** - safe marker payload
- **SQLi Error Disclosure** - `'` injection (safe)
- **Directory Listing** - Index of/
- **Security.txt & robots.txt** - RFC 9116
- **Mixed Content & SRI** - http on https, missing integrity
- **HTTPS Redirect** - http → https

Example output (pixelcity.top):
```
Iris WebScan v1.1.0 - Deep website audit on https://pixelcity.top
WebScan completed in 0.27 seconds
Found 2 issues  MEDIUM:1 LOW:1
```

## Reporting & Compliance

Every finding mapped to **OWASP Top 10, CWE, SOC 2, ISO 27001, GDPR** (`internal/config/config.go:14`). Table shows `Risk Score` (Critical 40, High 10, Medium 3, Low 1) + `Risk Level` (Excellent/Low/Medium/High/Critical). HTML is executive report: risk meter, exposure bar, compliance grid, prioritized fix plan.

```bash
iris scan . --format html --output report.html
iris scan . --format sarif --output results.sarif
iris scan . --format cyclonedx --output sbom.json
iris webscan https://example.com --compliance soc2 --format html --output ws.html
iris fmt . --check --format sarif --output fmt.sarif
```

## CI/CD

### GitHub Actions

```yaml
- uses: iris/iris-action@v1
  with:
    scan-type: 'sast,sca,secrets,webscan,format'
    severity: 'high,critical'
    compliance: 'soc2,owasp'
    format: 'sarif'
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: results.sarif }
```

### GitLab CI

```yaml
iris:
  image: iris/iris:latest
  script:
    - iris fmt . --check            # formatting gate
    - iris scan . --profile enterprise --format sarif --output gl-sast.json
    - iris scan . --format cyclonedx --output sbom.json
  artifacts: { reports: { sast: gl-sast.json }, paths: [sbom.json] }
```

### Pre-commit

```yaml
repos:
  - repo: https://github.com/Pixelcity-dev/Iris
    rev: v1.1.0
    hooks:
      - {id: iris-secrets}
      - {id: iris-sast}
      - {id: iris-format}   # fmt --check
```

### Policy Gate

```bash
iris scan . --fail-on HIGH
iris fmt . --check          # or --fail-on LOW for style
```

## Output Formats

| Format | Use |
|--------|-----|
| **Table** | Terminal, CI logs — risk score + compliance, grouped by severity |
| **HTML** | Executive report — risk meter, compliance grid, fix plan |
| **JSON** | Automation — `jq` friendly |
| **SARIF 2.1.0** | GitHub Code Scanning, SonarQube, SIEM |
| **CycloneDX/SPDX** | SBOM, supply-chain |
| **JUnit/CSV** | Test gates, spreadsheets |

`--format html|table|json|sarif|cyclonedx|spdx|junit|csv` + `--output`

## PixelCity Cloud & Dashboard

Connect Iris to your PixelCity account (create one at **https://id.pixelcity.dev**):

```bash
iris cloud login      # device flow — opens id.pixelcity.dev, enter the code
iris cloud status     # plan, quotas (scans, AI pages), features
iris cloud usage      # recent scan history
iris cloud upgrade pro        # checkout via payments.pixelcity.dev
iris cloud upgrade enterprise --interval yearly
```

**Dashboard** — https://dashboard.pixelcity.dev — account management (Keycloak),
usage history, Pro/Enterprise plans, and the public roadmap incl. the
**Upcoming Features** docs (AI Agent with active usage limits and **no model
training** — your code never trains models).

Deploy your own dashboard? See `deploy/RUNBOOK.md` (Caddy + Keycloak + docker).

## Roadmap — Upcoming Features

See [docs/upcoming-features.md](docs/upcoming-features.md) for the announced,
docs-only roadmap: **AI Agent** (fair-use limits, zero-retention, no training),
Teams & Organizations, Scheduled Cloud Scans, IDE extensions.

## Plugin System

```bash
iris plugin search sast
iris plugin install custom-scanner --registry https://plugins.yourco.dev
iris plugin list
```

## MCP Server — AI-Native

```bash
iris mcp start   # stdio/SSE
```

Tools: `iris.scan`, `iris.findings`, `iris.explain`, `iris.suggest-fix`, `iris.fmt`

## Deployment

```bash
# Air-gapped
iris db update --cache-dir /mnt/cache && tar czf iris-db.tar.gz ~/.iris/cache
# Server
iris server start --host 0.0.0.0 --port 8443 --tls
# Formatter only (zero db)
iris fmt . --fix
```

## Documentation

- [User Guide](docs/user-guide.md) • [Rule Authoring](docs/rules.md) • [Plugin Dev](docs/plugins.md) • [API](docs/api.md)
- Full Docs: **https://pixelcity.top/docs/iris** • **https://pixelcity.dev/docs/iris** • **https://cdn.pixelcity.dev/docs/iris**

## About PixelCity

**PixelCity — Your Cloud, Your Rules** — https://pixelcity.top — `service@pixelcity.dev`

Iris is developed and operated by **PixelCity** as a public open-source project for the community. Infrastructure served via `Caddy → pixelcity-cdn` (`cdn.pixelcity.dev`, `cdn.pixelcity.top`). Status at https://status.pixelcity.top.

## Contributing & License

Contributions via PR — see `CONTRIBUTING.md`. Security reports and help: `service@pixelcity.dev`.

**Apache 2.0** — `LICENSE` — `https://pixelcity.top` — Copyright © PixelCity. Public since **v1.1.0**.
