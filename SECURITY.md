# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

- Email: **service@pixelcity.dev**
- Or use GitHub's [private vulnerability reporting](https://github.com/Pixelcity-dev/iris/security/advisories/new)

Include the Iris version (`iris --version`), your OS and architecture, a
reproduction, and the impact you believe the issue has. If the report concerns a
scanner rule, include the sample input you used — but never send real
credentials, customer data, or production dumps.

## Scope

In scope:

- the Iris CLI and its scanners
- the installer (`install.sh`) and release binaries
- the GitHub Action in `.github/actions/iris`

Out of scope:

- findings that Iris reports about *your* code — those are for you to fix
- missing detections ("Iris did not flag X") reported without a sample
- vulnerabilities in third-party dependencies that upstream has not fixed yet
  (report them upstream; we will bump when a fix ships)

## What to expect

- Acknowledgement within 5 business days
- An assessment and rough timeline within 10 business days
- Credit in the release notes once a fix ships, unless you ask to stay anonymous

## Safe harbour

We will not pursue legal action for good-faith research that follows this
policy, stays within your own systems, and does not access, modify, or retain
other people's data. Do not run destructive scans, denial-of-service tests, or
testing against third-party infrastructure you do not own.
