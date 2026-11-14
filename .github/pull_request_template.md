## What this changes

<!-- One or two sentences. Link the issue or discussion if there is one. -->

## Why

<!-- The problem this solves. For detection changes: what is missed today and why it matters. -->

## How it was tested

<!--
Paste the commands you ran, e.g.
  go test ./...
  ./bin/iris scan ./testdata/fixtures/... --scanner sast
-->

## Checklist

- [ ] `gofmt -l .` prints nothing
- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] New behaviour has tests
- [ ] No live secrets, real domains, or customer data in fixtures, commits, or this description
- [ ] Any new rule lives in `rules/` and includes ID, severity, and description
