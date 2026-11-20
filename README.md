<p align="center">
  <img src="assets/iris-wordmark.svg" alt="Iris Security Platform" width="360">
</p>

<p align="center">
  Security scanning for source code, dependencies, infrastructure, containers, and websites.
</p>

<p align="center">
  <a href="LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-5bd3a7?style=flat-square"></a>
  <a href="https://github.com/Pixelcity-dev/iris/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Pixelcity-dev/iris/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Pixelcity-dev/iris/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/Pixelcity-dev/iris?style=flat-square"></a>
  <img alt="Go version" src="https://img.shields.io/github/go-mod/go-version/Pixelcity-dev/iris?style=flat-square">
  <a href="https://goreportcard.com/report/github.com/Pixelcity-dev/iris"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/Pixelcity-dev/iris?style=flat-square"></a>
</p>

<p align="center">
  <code>curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh</code>
</p>

<p align="center">
  <a href="https://pixelcity.top/docs/iris">Documentation</a>
</p>

Iris is an open-source security scanner for source code, dependencies, infrastructure, containers, and websites. The built-in scanners are compiled into one Go binary and work offline.

Run it locally, use it as a CI gate, or point it at a site you are authorized to test. Nothing is uploaded unless you sign in to the optional PixelCity dashboard. Iris is developed by [PixelCity](https://pixelcity.dev) and released under Apache 2.0.

> **Test only what you own or are authorized to test.** Iris reports potential security issues to help you investigate and remediate them. A clean scan is not a guarantee of security or compliance.

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Quick start](#quick-start)
- [Scanner coverage](#scanner-coverage)
- [Reports](#reports)
- [Baselines](#baselines)
- [CI integration](#ci-integration)
- [Configuration](#configuration)
- [Command reference](#command-reference)
- [Privacy](#privacy)
- [Project status](#project-status)
- [Development](#development)
- [Contributing and security](#contributing-and-security)
- [License](#license)

## What it does

- **One static binary.** The scanners are compiled in; the built-in checks need no language toolchain.
- **Local-first.** Source and findings stay on your machine. Only the website and network scanners make outbound requests.
- **Fast enough to run often.** Rule-based scans finish in milliseconds, which makes pre-commit and CI use practical.
- **CI output.** SARIF for GitHub Code Scanning, JUnit for test reporters, exit codes for gates, and JSON for everything else.
- **Rules are data.** Built-in rules are embedded in the binary; project rules in `rules.paths` override them by ID.
- **Cross-platform.** Release builds for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64).

## Install

### Install script (recommended)

```sh
curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
iris --version
```

The installer selects the release asset for your platform (`iris-<os>-<arch>`), verifies its SHA-256 checksum, and installs to `~/.local/bin` by default.

```sh
# Install a specific version or into a different directory
curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | IRIS_VERSION=v1.2.0 sh
curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | INSTALL_DIR="$HOME/bin" sh
```

### Go

Requires Go 1.27 or newer.

```sh
go install github.com/Pixelcity-dev/Iris/cmd/iris@latest
iris --version
```

### Build from source

```sh
git clone https://github.com/Pixelcity-dev/iris.git
cd iris
make build
./bin/iris --version
```

### Docker

The repository includes a multi-stage [Dockerfile](docker/Dockerfile). Build it locally:

```sh
docker build -f docker/Dockerfile -t iris .
docker run --rm iris --help
```

### Verify the install

```sh
iris --version
iris --help
```

Downloadable binaries and checksums are on the [releases page](https://github.com/Pixelcity-dev/iris/releases).

## Quick start

```sh
# Scan the current repository with the default filesystem scanners
iris scan .

# Run a focused set of scanners and fail on high or critical findings
iris scan . --scanner sast,sca,secrets --severity high --exit-code

# Audit a website you are authorized to test
iris webscan https://example.com

# Write a SARIF report for GitHub Code Scanning
iris scan . --format sarif --output iris-results.sarif

# Check or fix formatting
iris fmt . --check
iris fmt . --fix

# Create a project configuration file
iris init
```

`iris scan` accepts a directory, repository, container reference, or URL. `iris webscan` is the focused entry point for websites and performs deeper checks than the `dast` scanner alone.

## Scanner coverage

| Scanner | What it checks | Targets |
| --- | --- | --- |
| `sast` | YAML-driven pattern rules for SQL injection, XSS, command injection, path traversal, weak cryptography, and hardcoded credentials. Supports Go, Python, JavaScript/TypeScript, Java, Rust, Ruby, PHP, C#, C/C++, Kotlin, and Swift. | directories, repositories |
| `secrets` | 18 credential patterns covering AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio, SendGrid, Heroku, private keys, JWTs, passwords in URLs, and connection strings. Matched values are redacted in output. | directories, repositories |
| `sca` | Dependency inventory from nine manifest formats: `go.mod`, `package.json`, `requirements.txt`/`Pipfile`, `pom.xml`, `build.gradle`, `Cargo.toml`, `Gemfile`, `composer.json`, and `*.csproj`. | directories, repositories |
| `iac` | Dockerfile, Terraform/HCL, and Kubernetes checks: unpinned images, public S3 ACLs, `0.0.0.0/0` ingress, privileged pods, host networking, and disabled logging. | directories, repositories |
| `container` | Dockerfile checks: exposed SSH, root user, privileged mode, and host networking. | Dockerfile |
| `dast` | Security headers, HSTS, TLS, cookies, CORS, information disclosure, clickjacking, HTTPS redirect, and risky HTTP methods. | URL |
| `webscan` | DAST plus deeper checks: CSP analysis, certificate expiry, exposed files, directory listing, mixed content/SRI, `security.txt`, and safe reflected-XSS, SQL-error, and open-redirect probes. | URL |
| `network` | 22 common TCP ports and dangerous exposed services. | host or CIDR |
| `license` | License-file detection and SPDX-style license identification, including a copyleft flag. | directories, repositories |
| `format` | Seven formatting checks: trailing whitespace, missing EOF newline, CRLF endings, mixed indentation, long lines, `gofmt` drift, and consecutive blank lines. Auto-fix with `iris fmt --fix`. | directories |
| `buildtest` | Detects Go, Node.js, Rust, Maven, Gradle, and Python projects, then runs their standard build/test commands and reports failures as findings. | directories, repositories |

Scanner coverage is deliberately narrow and evolving. See [Project status](#project-status) for what is production-ready today.

## Reports

Choose one or more formats with `--format` and write them with `--output`.

| Format | Use it for |
| --- | --- |
| `table` | Human-readable terminal output (default) |
| `json` | Full machine-readable results |
| `sarif` | SARIF 2.1.0 for GitHub Code Scanning and other SARIF consumers |
| `cyclonedx` | CycloneDX 1.5 JSON |
| `spdx` | SPDX JSON |
| `html` | A self-contained report you can share |
| `csv` | Spreadsheets and ad-hoc analysis |
| `junit` | CI test reporters |

```sh
iris scan . --format html --output iris-report.html
iris scan . --format cyclonedx --output iris-sbom.json
iris scan . --format table,json --output results
```

With multiple formats and `--output`, Iris appends the format extension to each file.

`--exit-code` makes the scan exit non-zero when findings remain after the `--severity` filter. Use it to turn any scanner into a policy gate:

```sh
iris scan . --severity high --exit-code
```

## Baselines

Accept the findings you already know about, then fail only on new ones:

```sh
# Capture the current state
iris scan . --format json --output iris-current.json
iris baseline create --from iris-current.json

# Later: report and gate only new findings
iris scan . --baseline .iris-baseline.json --exit-code

# Inspect new findings from a saved scan
iris baseline diff --from iris-current.json --exit-code
```

Baselines match on rule, file, and title, so moving code does not turn an accepted finding into a new one. Commit `.iris-baseline.json` if the team agrees the current findings are accepted, and review baseline changes like any other security decision.

## CI integration

Iris ships a composite GitHub Action at [`.github/actions/iris`](.github/actions/iris/action.yml):

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [master]

permissions:
  contents: read
  security-events: write

jobs:
  iris:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Iris
        uses: Pixelcity-dev/iris/.github/actions/iris@v1.2.0
        with:
          scan-type: sast,sca,secrets
          severity: high
          format: sarif
          output: iris-results.sarif
          upload-code-scanning: true
```

Or install the CLI yourself and upload the report separately:

```yaml
- name: Install Iris
  run: |
    curl -fsSL https://cdn.pixelcity.dev/iris/install.sh | sh
    echo "$HOME/.local/bin" >> "$GITHUB_PATH"

- name: Scan
  run: |
    iris scan . --scanner sast,sca,secrets --severity high \
      --format sarif --output iris-results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: iris-results.sarif
```

`iris generate github-action` writes a starter workflow; `iris generate pre-commit` and `iris generate gitlab-ci` are also available.

## Configuration

Run `iris init` to scaffold `.iris.yaml`. The scanner toggles are applied when Iris starts; control each run with `--severity`, `--format`, and `--output`.

```yaml
version: 1.2.0

scanners:
  sast: true
  sca: true
  secrets: true
  iac: true
  container: true
  dast: true
  network: true
  license: true
  webscan: true
  format: true
  buildtest: false
```

The scaffold also contains report and filter sections. `report.format`, `filter.min_severity`, and `filter.compliance` are applied when the matching flag is not passed on the command line.

Built-in rules are compiled into the binary, so `iris scan .` works from any directory and offline. To add project-specific rules, point `rules.paths` at a directory of YAML files:

```yaml
rules:
  builtin: true
  paths:
    - ./.iris-rules
```

A rule with the same `id` as a built-in replaces it, which is how you tune a noisy detection without forking the scanner. Patterns are Go regular expressions; `||` is accepted as an alternation for older rule files.

Iris looks for configuration in this order:

1. `--config <path>`
2. `.iris.yaml`
3. `iris.yaml`
4. `.iris.yml`
5. `iris.yml`
6. `~/.config/iris/config.yaml`

## Command reference

| Command | What it does |
| --- | --- |
| `iris scan <target>` | Run one or more scanners against a directory, repository, container, or URL. `--exclude`/`--include` accept file globs (`**` supported); `--profile startup\|business\|enterprise` applies scanner and threshold presets |
| `iris webscan <url>` | Deep website security audit |
| `iris fmt <path>` | Check or fix formatting (`--check`, `--fix`, `--diff`) |
| `iris buildtest <path>` | Run the detected build and test commands as a gate |
| `iris init` | Create `.iris.yaml` |
| `iris rule list\|search\|info\|stats` | Inspect the built-in rule set |
| `iris explain <id>` | Show a rule's description, severity, and remediation |
| `iris show <file>` | Render a saved JSON scan in any report format (`--format`, `--output`) |
| `iris convert -i <file> -f <format>` | Convert between report formats |
| `iris baseline create --from <scan.json>` | Save accepted findings as a baseline |
| `iris baseline diff --from <scan.json>` | Show only findings that are new since the baseline |
| `iris generate ...` | Generate GitHub Actions, GitLab CI, or pre-commit configuration |
| `iris cloud login\|status\|usage\|show\|upgrade\|logout` | Optional PixelCity account and dashboard history |

The following commands exist but are early scaffolding rather than finished features: `db`, `mcp`, `plugin`, and `server`. They are documented in [Project status](#project-status) and are not required for scanning.

## Privacy

- No telemetry and no background network calls.
- Built-in file scanners read only the target path you give them.
- Scans never require an account. If no PixelCity session exists, dashboard upload is skipped.
- After `iris cloud login`, results can be saved to your dashboard scan history. Use `--no-upload` to disable this unconditionally, or `iris cloud logout` to remove the session.
- Website and network scans make outbound requests by design. Run them only against systems you are authorized to test.

## Project status

Iris is under active development. The most mature paths today are secret scanning, Dockerfile/IaC checks, website header/TLS checks, formatting, build/test failure reporting, and baseline suppression.

Known limits:

- SAST is rule-driven and pattern-based. The built-in patterns target obvious single-line matches and should not replace a dedicated SAST tool; expect limited coverage and false positives.
- SCA inventories dependency manifests (including `go.mod` require blocks). It does not yet correlate packages with CVE feeds.
- Some convenience commands (`db`, `mcp`, `plugin`, `server`) are scaffolds; they do not provide production behavior yet.
- Detection quality and coverage improve release by release. Validate findings before using them as a hard production gate.

If you find a coverage gap or a false positive, a reproducible example in an issue is the most useful contribution.

## Development

Requirements: Go 1.27 or newer, GNU Make, and git.

```sh
make build          # bin/iris
make test           # go test ./...
make vet            # go vet ./...
gofmt -l .          # should print nothing
```

The dashboard is a separate Go module:

```sh
make build-dashboard
make test-dashboard
```

Useful flags while iterating:

```sh
./bin/iris scan . --no-color --verbose
./bin/iris scan . --scanner secrets --format json
```

## Contributing and security

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) for the setup, the testing bar, and the redaction rule for fixtures. Questions and rule ideas are fine in [Discussions](https://github.com/Pixelcity-dev/iris/discussions); larger changes should start as an issue.

Please report vulnerabilities privately via [SECURITY.md](SECURITY.md) or [GitHub advisories](https://github.com/Pixelcity-dev/iris/security/advisories/new), never in a public issue. Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Iris is distributed under the [Apache License 2.0](LICENSE). Copyright © PixelCity.

## PixelCity

- [Homepage](https://pixelcity.dev)
- [Documentation](https://pixelcity.top/docs/iris)
- [Discord support](https://discord.gg/8BxaVG6fFm)
- [Email support](mailto:service@pixelcity.dev)
