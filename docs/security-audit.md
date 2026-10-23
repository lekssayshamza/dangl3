# V2 security audit

Audit baseline: 194 offline tests passed on Python 3.14.7 before modifications.
The six core modules, input handling, reporting, tests and bundled database were
reviewed before implementation. No live claimability experiment was performed.

## Findings and remediation

| Finding | V2 remediation | Regression coverage |
| --- | --- | --- |
| V1 already pins HTTP URLs to validated IP literals and supplies original Host/SNI. Validating DNS alone would be insufficient. | Preserve this connection-level boundary in both sync and async clients; disable proxies and TLS bypasses. | Fake network backends assert actual TCP IP, Host, SNI and certificate verification settings. |
| Terminal A/AAAA queries may follow a newly introduced CNAME not present in the recorded traversal. | Reject mismatched answer canonical names; validate CNAME targets and address families. | DNS canonical-name drift and malformed-answer tests. |
| `ipaddress` special-use classifications vary between supported Python versions; scoped IPv6 and Azure's platform virtual IP need explicit treatment. | Add conservative explicit special-use blocks, reject IPv6 scope IDs and transition mechanisms, and require every answer to be public. | Mixed-answer, metadata, scoped-address and IPv4/IPv6 special-range tests. |
| V1 re-resolves the entire CNAME chain before the first HTTP request. This can disconnect attribution from the HTTP snapshot. | Reuse the validated initial DNS snapshot, pin its address, re-resolve redirects and HTTP fallback; record changed CNAME attribution. | Rebinding between validation and connection, redirect/fallback changes, and query-count tests. |
| IP-keyed connection pools shared between targets could reuse a TLS session under another hostname when adding concurrency. | Each target owns its own client/pool; only same-target requests can reuse connections. | Two-host/same-IP transport tests and cancellation cleanup tests. |
| A truncated body without negative conditions could still match. Redirected error pages could be treated like errors at the requested root. | Truncated/incomplete bodies never match; redirected matches are at most suspicious; conflicting negative indicators are explicit. | Truncation, redirect and conflict classification tests. |
| JSON duplicate keys and unknown rule fields silently override or weaken intended conditions. JSON size, nesting and rule sizes lack bounds. | Bound input bytes, definitions and strings; reject duplicate keys, unknown fields, malformed URLs, headers and review dates. Disable an entire invalid provider. | Malicious/oversized/ambiguous database tests. |
| Target files and individual lines have no explicit size limit. Invisible IDNA characters can be silently discarded. | Bound file bytes, line length and unique targets; reject invisible/control hostname characters. | Input-limit and Unicode regression tests. |
| Synchronous I/O and socket inactivity timeouts do not provide bounded async cancellation or an absolute request deadline. | Native async DNS/HTTP, a fixed worker pool, per-request wall-clock deadlines and awaited task/client cleanup. | Worker/task counts, slow streams, timeout, cancellation and cleanup tests. |

The explicit Azure platform-address block follows
[Microsoft's description of its virtual public IP](https://learn.microsoft.com/en-us/azure/virtual-network/what-is-ip-address-168-63-129-16),
which exposes platform communication over HTTP inside Azure despite being a
public IP literal. This is why a global-address predicate alone is insufficient.

## Residual boundaries

The operating system, configured recursive DNS resolver, installed CA store and
network routing are trusted. IP pinning prevents hostname re-resolution from
changing the TCP destination; it cannot defend against malicious routing,
transparent network interception, locally configured translation of otherwise
public IPs, or a compromised OS. DNSSEC and authoritative ownership are not
verified. HTTP content is unauthenticated when plain HTTP is used. TLS fallback
is recorded and cannot establish claimability. Provider error pages can be
imitated; no positive classification proves that a resource can be registered.

The response inspection cap bounds retained body bytes, not every byte already
buffered by the HTTP/network stack. DNS replies and HTTP headers also have
library protocol limits. The input list and results use memory proportional to
the configured hard limit of 10,000 unique targets; task creation is bounded by
concurrency, not input size. Custom injected test transports/resolvers are trusted
Python dependencies, not a sandbox for arbitrary extensions.
