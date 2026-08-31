# Contributing

Thanks for your interest in contributing. Please read this through before
opening an issue or pull request.

## Reporting bugs and suggesting features

Use GitHub issues. Before opening one, search existing and recently closed issues
to avoid duplicates. A useful report includes:

- A reproducible test case or a sequence of steps
- The version of this project being used
- Which deployment configuration you used (paste the relevant `config/*.yaml`,
  with account IDs, hostnames, and ARNs redacted)
- Anything unusual about your environment

**Do not report security issues through GitHub.** See [SECURITY.md](SECURITY.md).

## Contributing code

1. Work against the latest `main`.
2. Check existing open and recently merged pull requests so you are not
   duplicating effort.
3. Open an issue first for anything substantial. A large PR that does not fit the
   project's direction wastes your time and ours.

Then:

```bash
git checkout -b my-change
# make changes
make lint test          # must pass
git commit -m "feat: describe the change"
```

Send the pull request with a clear description, and reference any related issue.

### What we ask of a change

- **Tests pass and new behaviour is tested.** `make test` runs unit tests with a
  mocked PRTG API, so it needs no AWS account and no PRTG server.
- **`make synth-all` passes.** This synthesises every configuration in `config/`.
  A change that only works for the default configuration is not finished - the
  point of this sample is that the five configuration knobs are independent.
- **Security posture is preserved.** In particular: the PRTG tool surface stays
  read-only, IAM policies stay scoped to specific ARNs, and TLS verification
  stays on by default. If a change needs to relax one of these, say so
  explicitly in the PR description and explain why.
- **No secrets, account IDs, IP addresses, hostnames, or customer names.**
  `make check-sanitisation` catches credential shapes, AWS keys and internal
  hostnames - but **not** bare IP addresses, and nothing text-based can inspect a
  rendered image. Check those yourself. If your change adds or regenerates a
  diagram, read [`docs/images/README.md`](docs/images/README.md) first for the
  labels-and-crop checklist.
- **Docs updated.** If you add a configuration option, it belongs in
  `docs/deployment-matrix.md` and in the config schema.
- Keep commits focused. Unrelated reformatting makes review harder.

### Adding a PRTG tool

If you add a tool, add it to `src/prtg_mcp/tools.py` only. The schema there is
the single source of truth: the Lambda dispatch table and the AgentCore Gateway
target schema are both derived from it, so they cannot drift apart. A test
asserts this, and it will fail if you define a tool the handler cannot serve or
vice versa.

New tools must be read-only. A tool that mutates PRTG changes the security
assessment of the whole integration - see
[`docs/security.md`](docs/security.md#why-read-only-matters). If you need
mutating behaviour, that is a fork, not a contribution.

## Code of conduct

This project follows the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).

## Licensing

This project is licensed under MIT-0. We may ask you to confirm the licensing of
your contribution.
