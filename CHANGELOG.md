# Changelog

## 0.2.0 — 2026-10-23

### Security

- Audit the DNS, HTTP, provider, fingerprint, scanner and model boundaries;
  preserve V1's literal-IP TCP pinning with original Host/TLS SNI verification.
- Reject canonical-name drift during terminal address queries, malformed CNAME
  targets, address-family mismatches, scoped IPv6, explicit special-use/metadata
  ranges and mixed public/private destinations.
- Reuse the initial DNS snapshot for the first pinned request; revalidate
  redirects and HTTP fallback, and record changed provider attribution.
- Isolate HTTP pools/cookies between targets sharing IPs, retain verified TLS,
  and impose native async per-request wall-clock deadlines.
- Prevent truncated bodies from matching any rule; explain conflicting negative
  indicators, duplicate evidence headers and missing required headers.
- Restrict redirected/error-bearing matches to at most suspicious.
- Bound input files/lines/unique targets and fingerprint database definitions;
  reject invisible hostname characters, duplicate JSON keys, unknown fields,
  non-JSON constants, unsafe evidence headers and invalid metadata.

### Detection and coverage

- Add structured provider coverage, source review dates/bases and the
  `dangl3 providers [--verbose|--json]` command.
- Recognize the documented `vercel-dns-017.com` suffix and exact Netlify apex
  load-balancer hostname. Retain the 34 curated S3 website suffixes.
- Bound literal error-code matches to complete tokens; support optional exact
  HTML title conditions without executable expressions or user-supplied regex.
- Keep S3 and Vercel as the two active HTTP providers. Retain GitHub Pages,
  Azure, Heroku and Netlify as DNS-only after source review; do not activate
  speculative claimability indicators.
- Add synthetic provider-present, negative and ambiguous fixtures for all six
  providers, with provenance and explicit limitations.

### Performance, CLI and reporting

- Use native asyncio DNS/HTTP with a fixed worker pool (default 5, maximum 20),
  stable input ordering, per-target failures and cancellation cleanup.
- Avoid a task per input, duplicate first-request DNS queries, repeated CA-store
  loading and cross-host connection reuse. Reuse same-target connections for
  explicitly empty redirect responses.
- Preserve the synchronous scan entry point and trusted V1 injected fixtures.
- Extend report schema 1 additively: retain legacy fields and add scan/target
  durations, provider coverage, original inputs, structured evidence, explanations,
  limitations, warnings and transport/DNS inspection details.
- Retain atomic JSON writes and clean JSON stdout; add concise terminal totals
  and optional verbose evidence. Ctrl+C returns 130 without a partial report.
- Update the async offline demo, README, architecture, security audit, source
  archive contents and CI checks.
- Add the fully local UDP DNS, TCP HTTP and verified HTTPS integration lab,
  isolated fixture transport, deterministic concurrency checks and actual SIGINT
  cleanup coverage. All lab findings and TLS key material are synthetic.

### Verification

V1 baseline: 194 passing offline tests. V2: 339 offline tests passed locally on
Python 3.14.7, including the preserved V1 cases and new security, concurrency,
provider, CLI and reporting regressions.
The local integration lab adds 31 tests; the complete pre-publication suite
contains 370 tests.
No real-world detection-accuracy or claimability claim is made.

## 0.1.0 — 2026-10-23

- Initial Typer/Rich CLI, synchronous CNAME/A/AAAA resolution, six-provider DNS
  identification, S3/Vercel HTTP indicators and conservative classifications.
- Public-IP pinning, verified TLS, controlled redirects, bounded raw bodies,
  atomic JSON reports, packaging, offline demo and 194 offline tests.
