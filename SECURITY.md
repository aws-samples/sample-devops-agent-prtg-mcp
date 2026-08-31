# Security Policy

## Reporting a vulnerability

If you discover a potential security issue in this project, please notify AWS
Security via our [vulnerability reporting page](https://aws.amazon.com/security/vulnerability-reporting/)
or directly at aws-security@amazon.com.

**Please do not create a public GitHub issue for security findings.**

## Scope and intent of this sample

This repository is a **reference sample**. It is intended to demonstrate an
integration pattern and to be adapted before production use. Read
[`docs/security.md`](docs/security.md) for the threat model, the trust
boundaries, and the hardening decisions this sample makes.

Points worth understanding before you deploy:

- **The tool surface is read-only by design.** All nine PRTG tools issue HTTP GET
  requests against PRTG's read APIs. Nothing in the tool surface mutates PRTG
  state. This is the single most important security property of the integration
  and it should be preserved if you extend it. See
  [`docs/security.md`](docs/security.md#why-read-only-matters).
- **TLS verification is enabled by default.** Disabling it is possible but
  requires an explicit opt-out, and the handler logs a warning on every
  invocation when it is off. See
  [`docs/prtg-setup.md`](docs/prtg-setup.md#replace-the-shipped-certificate-before-trusting-it).
- **Use a read-only PRTG account.** The credential this integration holds should
  not be a PRTG administrator. PRTG aggregates credentials for the systems it
  monitors, which makes it a high-value target.
- **Least-privilege IAM is generated, not hand-written.** Policies are scoped to
  specific resource ARNs. If you replace them, keep them scoped.

## Your responsibilities

You are responsible for reviewing this sample against your own security
requirements, running your own assessment, and configuring it appropriately for
your environment. See the disclaimer in [`docs/security.md`](docs/security.md).
