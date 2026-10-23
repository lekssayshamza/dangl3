# Dangl3 v0.2.0

**Conservative subdomain takeover triage for authorized targets.**

Dangl3 is a Python 3.11+ CLI that follows DNS CNAME chains, identifies hosting
providers, checks narrowly defined HTTP indicators, and explains each result.
V2 adds bounded asynchronous scanning, stronger destination controls,
provider coverage metadata, and structured evidence. It does not prove resource
claimability or perform exploitation.

## What is subdomain takeover?

A CNAME maps a hostname such as `blog.example.com` to another DNS name, often a
hosting endpoint. If the hosted resource is removed while that pointer remains,
the DNS configuration may become dangling. Some provider configurations permit
another account to reuse the resource name or bind the domain, potentially
serving content under the organization's hostname.

DNS pointers and provider error pages identify configurations worth reviewing.
They cannot establish account ownership, domain verification, name reservations,
or actual claimability. Generic 404/403 responses, NXDOMAIN and TLS errors are
not proof of takeover.

## Features

- One hostname or a UTF-8 file, with strict normalization and stable deduplication.
- CNAME traversal, loop/depth checks, A/AAAA records and structured DNS failures.
- Six providers identified by explicit suffix or exact-hostname rules.
- Source-linked JSON fingerprints with bounded, validated definitions.
- Native async DNS/HTTP and a fixed worker pool: default 5, maximum 20.
- Connection-level IP pinning, original TLS hostname verification, and same-host redirects.
- Bounded raw HTTP bodies and per-request wall-clock deadlines.
- Deterministic output order, target isolation and cancellation cleanup.
- Rich tables and summaries, optional verbose evidence, and atomic JSON reports.
- Provider coverage command, offline fixtures, synthetic demo, and GitHub Actions.

## Installation: Kali and other Linux distributions

On Kali, Debian or Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv git
```

On Fedora use `sudo dnf install python3 python3-pip git`; on Arch use
`sudo pacman -S python python-pip git`. Python must be at least 3.11.
Clone the repository and install from its directory:

```bash
git clone https://github.com/lekssayshamza/dingl3.git dangl3
cd dangl3
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
dangl3 --version
dangl3 --help
```

For regular use, `python -m pip install .` omits development tools. These are
local-checkout installations, not a claim that a registry release is published.
Use a virtual environment instead of changing Kali's system Python.

## CLI usage

```bash
dangl3 scan -d blog.example.com
dangl3 scan -l subdomains.txt
dangl3 scan -l subdomains.txt -o report.json
dangl3 scan -l subdomains.txt --concurrency 5 --timeout 8
dangl3 scan -d blog.example.com --json > report.json
dangl3 scan -l subdomains.txt --json --verbose > report.json
dangl3 scan -d blog.example.com --max-cname-depth 10 --max-redirects 3
dangl3 providers
dangl3 providers --verbose
dangl3 providers --json
python -m dangl3 scan --help
```

Replace example names with targets you are explicitly authorized to assess.
Supply exactly one of `-d` or `-l`. Files contain one hostname per line; blank
lines and full-line `#` comments are ignored. First-seen order is preserved.
Valid names normalize to lowercase ASCII using Python's standard IDNA codec;
a single trailing DNS root dot is accepted. The original first input spelling
is retained separately in reports.

URLs, paths, credentials, ports, IP literals, wildcards, malformed labels and
invisible/control characters are rejected. The whole batch is validated before
network activity. Limits are 10,000 unique targets, a 16 MiB input file, and
4,096 characters per line, including comments. Results and inputs use O(N)
memory within that cap; queued tasks do not grow with N.

| Option | Default | Allowed values |
| --- | --- | --- |
| `--concurrency` | 5 | Integer 1–20 |
| `--timeout` | 5 seconds | Finite number greater than 0 and at most 120 |
| `--max-cname-depth` | 10 | Integer 1–50 |
| `--max-redirects` | 3 | Integer 0–10 |

Timeout applies to each DNS query and, in the production async client, each HTTP
request including redirect DNS validation, connect, TLS, headers and body reads.
It is not a whole-target or batch deadline. An initial HTTPS failure before any
response permits one HTTP fallback with fresh DNS validation. There are no automatic HTTP retries; DNS resolver attempts stay within each
query lifetime. S3 website targets use HTTP directly.

Normal output and diagnostics go to stderr. `--json` writes only JSON to stdout;
`--verbose` may additionally show detailed results on stderr. Reports use a
same-directory temporary file and atomic replacement. Parent directories must
exist. Existing report files are replaced; input files cannot be overwritten
through `-o`.

Exit code 0 means the batch completed, including findings and per-target errors.
Exit code 2 means invalid input/configuration or a database/output-file error.
Ctrl+C cancels the batch, closes native async resources and returns 130 without
writing a partial report. Review classifications and errors, not just exit status.

## Provider coverage

`dangl3 providers` displays actual capabilities, with sources and limitations
available through `--verbose` or `--json`. Source review dates are not live
claimability-verification dates.

| Provider | Recognized DNS patterns | Active HTTP fingerprint | Maximum HTTP finding |
| --- | --- | --- | --- |
| GitHub Pages | `*.github.io` | DNS only | `UNKNOWN` |
| AWS S3 websites | 34 explicit commercial-region website suffixes, in their documented dot/dash form | 404, specific missing-bucket code/message, AmazonS3 header, no conflicting indicators | `POTENTIAL_TAKEOVER` |
| Azure App Service | `*.azurewebsites.net` | DNS only | `UNKNOWN` |
| Heroku | `*.herokudns.com`, `*.herokuapp.com` | DNS only | `UNKNOWN` |
| Vercel | `*.vercel-dns.com`, `*.vercel-dns-017.com`, `*.vercel.app` | 404 with the documented bounded missing-deployment code | `SUSPICIOUS` |
| Netlify | `*.netlify.app`, exact `apex-loadbalancer.netlify.com` | DNS only | `UNKNOWN` |

A recognized provider CNAME ending in NXDOMAIN or no address records can be
`SUSPICIOUS`, including for DNS-only providers. Recognition never suffices for
`POTENTIAL_TAKEOVER`. Unknown and multi-provider chains remain `UNKNOWN`.

V2 deliberately retains four DNS-only providers. The source review did not
establish sufficiently reliable current unclaimed-resource HTTP contracts for
them. Heroku's official error template was retrieved, but that does not verify
current router status behavior or domain claimability. No speculative rule was
activated to inflate coverage.

The bundled [database](dangl3/data/providers.json) includes per-provider patterns,
capabilities, sources, review basis/date and limitations. See
[provider research and fixture provenance](docs/provider-research.md) for the
review decisions. Dates refer to documentation/template review; no live
unconfigured-resource or claimability test was performed for this release.

## Detection methodology

1. Validate and deduplicate all inputs, preserving the original first spelling.
2. Query absolute CNAME names without local search suffixes. Preserve each hop
   and terminal A/AAAA records. Reject loops, excessive depth, malformed CNAME
   targets and canonical-name changes discovered during address queries.
3. Identify providers using complete DNS label boundaries or exact names.
   `owner.github.io` matches; `github.io.attacker.example` does not.
4. Inspect fully resolved recognized targets at the supplied hostname. Reuse the
   initial DNS snapshot for the first pinned request. Fetch neither provider
   endpoints nor page assets separately.
5. Match every rule's status, bounded literal body indicators and required exact
   headers. Incomplete/truncated bodies never match. Negative indicators,
   duplicate evidence headers and missing required headers are explained as
   conflicting or ambiguous evidence.
6. Apply conservative classification. Redirected matches, changed DNS attribution,
   experimental matches and HTTP fallback errors cannot produce a potential
   finding. A provider's own missing URL without a customer CNAME is at most suspicious.

| Classification | Meaning |
| --- | --- |
| `POTENTIAL_TAKEOVER` | Provider CNAME plus a maintained, specific unconfigured-resource indicator, complete response and no recorded conflicts/redirects. Claimability remains unverified. |
| `SUSPICIOUS` | Provider-related dangling DNS or a limited/redirected resource indicator warrants review. |
| `NO_EVIDENCE` | Completed supported checks found no maintained indicator, or only a bare NXDOMAIN was observed. This is not proof of safety. |
| `UNKNOWN` | Unsupported/ambiguous service, DNS-only HTTP coverage, operational errors, conflicting evidence, or incomplete inspection prevents classification. |

Evidence categories are `DNS_PROVIDER_MATCH`, `HTTP_FINGERPRINT_MATCH`,
`HTTP_AMBIGUOUS`, `DNS_ERROR`, `HTTP_ERROR`, and `DETECTION_LIMITATION`.
No numerical confidence or vulnerability score is invented.

## Concurrency and security controls

The CLI uses native dnspython asynchronous resolution and httpx asynchronous
requests. A fixed pool processes at most `min(concurrency, targets)` targets;
it never creates a task per input. Single-target scans skip worker-task creation.
Workers write results into their input positions. One target failure does not
cancel others, and cancellation propagates through the worker group and client
contexts. The database is loaded once per batch.

**DNS validation controls the actual connection destination.** The HTTP URL sent
to the transport contains a validated literal public IP. The Host header and TLS
SNI contain the original requested hostname; certificate checks remain enabled
for that hostname. There is no unrestricted hostname lookup before connecting.
Every answer must satisfy the destination policy; mixed public/private answers
are blocked. Redirects and HTTP fallback get fresh DNS validation.

Private, loopback, link-local, multicast, reserved, shared-address and metadata
ranges are blocked, including Azure's platform virtual IP. Scoped IPv6,
IPv4-mapped IPv6, NAT64 well-known prefixes, 6to4 and Teredo are rejected.
Conservative explicit blocks supplement Python's version-dependent `ipaddress`
tables. There is no option to bypass these controls.

Redirects require the exact original hostname, HTTP/HTTPS standard ports, no
credentials, and no HTTPS downgrade. Sibling-domain redirects are also blocked.
Clients/pools are isolated per target so two hostnames sharing an IP cannot reuse
one another's TLS connection or cookies. Explicitly empty redirect responses can
reuse a connection within the same target; other redirect bodies close unread.
Environment proxies and netrc credentials are disabled.

Requests are GET only, with `Dangl3/0.2.0` in the User-Agent. Bodies retain at most
64 KiB of raw bytes by default; unexpected compression is rejected rather than
decompressed. No JavaScript, forms, POST requests, resource claiming or asset
fetching occurs. Full bodies and cookies never enter reports. At default settings
a target uses at most five HTTP requests: one failed HTTPS attempt followed by
HTTP with up to three redirects, or up to four requests on its initial scheme.

Fingerprint files have a 1 MiB limit and bounded definition/string counts. The
loader rejects duplicate keys, non-JSON constants, unknown fields, malformed
headers and review metadata. Rules use literals and fixed token boundaries,
not arbitrary regex or code. Invalid providers are disabled with warnings;
a malformed/unusable database is an actionable CLI error. Source links are
metadata and are never fetched during scans.

See the [security audit](docs/security-audit.md) and
[architecture](docs/architecture.md) for the trust boundaries and regression coverage.

## JSON reports and terminal output

V2 extends **schema version 1 additively**. Existing fields and their types remain:
`tool`, `scan_timestamp`, `total_targets`, `configuration`, `summary`, `warnings`,
`results`, and each result's `hostname`, `dns`, `provider`, `http`,
`matched_fingerprints`, `classification`, string-list `evidence`, and `errors`.
Strict consumers must tolerate the new fields.

New fields include batch/target `duration_seconds`, `duration_basis`, full
`provider_coverage`, top-level errors, `original_hostname`, `structured_evidence`,
`explanation`, `limitations`, and target warnings. HTTP details add attempted
connection addresses, DNS chain snapshots, conflicts and inspected byte counts.
An address records the attempted transport destination, not proof of successful
connection. The CLI supplies wall-clock batch duration. For standalone
`build_report` calls without batch timing, `duration_basis` explicitly records
that target durations were summed instead.

This abbreviated synthetic JSON illustrates the added fields; omitted sections
are present in real reports:

```json
{
  "schema_version": 1,
  "tool": {"name": "Dangl3", "version": "0.2.0"},
  "scan_timestamp": "2026-10-23T00:00:00Z",
  "duration_seconds": 0.01,
  "duration_basis": "wall_clock",
  "total_targets": 1,
  "configuration": {"concurrency": 5},
  "summary": {"POTENTIAL_TAKEOVER": 1, "SUSPICIOUS": 0, "NO_EVIDENCE": 0, "UNKNOWN": 0},
  "results": [{
    "hostname": "blog.example.com",
    "original_hostname": "Blog.Example.com.",
    "classification": "POTENTIAL_TAKEOVER",
    "matched_fingerprints": ["s3-website-no-such-bucket"],
    "duration_seconds": 0.009,
    "explanation": "Specific missing-bucket evidence matched; resource claimability has not been verified."
  }]
}
```

Normal terminal output shows Target, DNS, Provider, HTTP and Finding columns,
then target counts, elapsed time, classification totals and error count.
`--verbose` additionally shows each target's CNAME chain, evidence and diagnostics.

Run a fully offline V2 demonstration with three synthetic targets:

```bash
python examples/offline_demo.py > /tmp/dangl3-v2-demo.json
python -m json.tool /tmp/dangl3-v2-demo.json
```

Expected fixture summary: one potential S3 finding, one suspicious Vercel finding,
and one GitHub Pages unknown. The report includes an explicit synthetic-data warning.

## Limitations and false positives

- This is triage, not ownership or exploit verification. Domain protection,
  reservations, account/tenant constraints and policy can prevent takeover.
- Provider text/headers can change, be imitated, cached or quoted in unrelated
  content. A matching page still needs manual review by the domain owner.
- Four providers remain DNS-only. New endpoints and unsupported services can be
  missed. No attribution from shared IP ranges, flattened CNAMEs or A/AAAA-only
  custom domains is attempted.
- The OS, CA store, recursive resolver and routing are trusted. Pinning prevents
  DNS rebinding from changing the TCP IP; it cannot defend against a compromised
  OS, transparent interception, or local translation/routing of public addresses.
  DNSSEC, authoritative DNS ownership and provider account state are not checked.
- Plain HTTP evidence is unauthenticated. The first validated address is used;
  other addresses and geographic edges are not probed. Split DNS, TLS problems,
  blocked legitimate redirects, non-UTF-8 bodies and body caps can yield unknowns
  or false negatives. Reserved transition/anycast ranges may be overblocked.
- The cap bounds retained body bytes; the network stack can already have buffered
  additional data. Headers and DNS messages also have library protocol limits.
- Python's standard IDNA codec uses its own normalization rules, rather than a
  configurable IDNA2008 implementation. Reports retain the original spelling.
- Trusted V1 synchronous resolver/inspector injection remains supported through
  bounded worker threads. Cancellation cannot forcibly stop an arbitrary injected
  synchronous function; only the default native async path has the stated async
  deadlines and cleanup guarantees.
- No new live target or claimability tests were performed for V2. Offline tests,
  documentation review and synthetic fixtures do not measure real-world detection accuracy.

## Development and testing

```bash
python -m pip install -e '.[dev]'
python -m pytest
dangl3 --help
dangl3 scan --help
dangl3 providers --json
python examples/offline_demo.py
python -m build
python -m pip check
```

The original V2 validation on Python 3.14.7 passed 339 offline tests. The suite
preserves all V1 test cases, with version assertions updated,
and expands DNS safety, actual TCP/SNI parameter checks, pooling isolation,
redirect/fallback rebinding, truncation/conflicts, per-provider fixtures,
concurrency bounds, ordering, cancellation, cleanup, JSON output and atomic writes.
A fixture blocks real socket connections, UDP sends and system address lookups
in the unit tests. The local integration tests instead permit only their exact
registered loopback endpoints and DNS replies to participating local clients.
Third-party targets are never required for CI. CI is configured for Python
3.11–3.14; that matrix is not a claim all versions were executed locally.

## Local integration lab

The [local integration lab](integration_lab/README.md) runs 12 synthetic scenarios
through the production scanner using real loopback UDP DNS, TCP HTTP, and HTTPS
with a dedicated test CA. It requires no cloud accounts, public DNS changes,
Docker, root privileges, or system DNS/trust-store changes.

```bash
python -m integration_lab.runner
python -m pytest -q tests/integration
```

The lab's private policy/transport pair permits only its assigned loopback ports
and exact fixture names. The production CLI has no bypass flag and retains its
normal SSRF/TLS restrictions. These simulated findings are not real vulnerabilities.

## Ethical usage

Scan only hostnames you own or have explicit authorization to assess. DNS queries
and GET requests are observable and may trigger monitoring. Follow engagement
scope and provider terms. Obtain separate authorization before any attempt to
register resources or demonstrate impact. Report potential issues responsibly.
Dangl3 performs no automatic enumeration, brute force, takeover exploitation,
credential collection, stealth, background monitoring or cloud account actions.

## V3 roadmap

- Gather owner-authorized, reproducible current provider error captures before
  activating additional fingerprints; retain review provenance and negative fixtures.
- Publish a formal machine-readable report schema and report comparison tools.
- Improve DNS diagnostics and optional owner-supplied inventory correlation.
- Evaluate safer address failover and rate controls using measured workloads.

See [CHANGELOG.md](CHANGELOG.md). Contributions should include sources, detection
limitations, and offline positive/negative/ambiguous tests. MIT licensed; see
[LICENSE](LICENSE).
