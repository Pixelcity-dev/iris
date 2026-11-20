# Contributing to Iris

Thanks for taking the time to improve Iris. This file describes how to get a
change from idea to merged.

## Before you start

- Open an issue for anything larger than a bug fix or a small documentation
  change. It is cheaper to agree on the approach first.
- Security issues go to [SECURITY.md](SECURITY.md), never to a public issue.

## Development setup

Requirements: Go 1.27 or newer, GNU Make, and git.

```sh
git clone https://github.com/Pixelcity-dev/iris.git
cd iris
make build      # bin/iris
make test       # go test ./...
```

Run the binary you just built with `./bin/iris --help`. If you have an older
`iris` on your `PATH`, call `./bin/iris` explicitly so you are testing your
change and not the installed release.

## What a good pull request looks like

- **One concern per pull request.** A new scanner rule and a refactor of the UI
  are two pull requests.
- **Tests.** New scanner behaviour needs a table-driven test with a small,
  synthetic fixture. Never commit real credentials, customer code, or production
  output — see the redaction rule below.
- **Formatting and vet.** `gofmt -l .` must print nothing and `go vet ./...` must
  pass; CI enforces both.
- **Rules are data.** Prefer adding a rule to `rules/builtin/` over hard-coding
  a check in Go. Include the rule ID, severity, CWE where applicable, and a
  short description. Rule patterns are Go regular expressions. Built-in rules
  are embedded with `go:embed`, so run `make build` after editing a YAML file;
  a running binary will not see uncommitted rule edits until it is rebuilt.
- **No new runtime dependencies** unless there is no reasonable way to avoid
  them. Iris ships as a single static binary and that is a feature.
- **Commit messages** follow `type(scope): summary`, for example
  `fix(webscan): root well-known probes at the site origin`.

## Redaction rule

Test fixtures, issues, and pull requests must not contain live secrets, real
domains you do not own, or personal data. Use `example.test`, `AKIAIOSFODNN7EXAMPLE`,
and obviously fake tokens. A scanner repository that leaks credentials is not a
good look.

## Review and release

- A maintainer reviews every pull request; expect questions about false
  positives and false negatives before merge.
- Releases are tagged `vX.Y.Z` on `master`. The tag triggers
  `.github/workflows/release.yml`, which builds the cross-platform binaries,
  generates `.sha256` files, and publishes the GitHub release.
- Add user-visible changes to the release notes by keeping the PR title
  descriptive; release notes are generated from commits.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
