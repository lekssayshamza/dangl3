# Provider review and fixture provenance

Sources reviewed on 2026-10-23. These are documentation reviews, plus a read of
Heroku's published static templates. No unconfigured third-party target was
probed and no account/resource claimability experiment was performed. A source
review date is not a statement that real-world detection accuracy was measured.

## AWS S3 website hosting

The [official error definition](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html)
documents the missing-bucket code/message and HTTP 404. The
[website error guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/CustomErrorDocSupport.html)
explains other causes of website 404s. The
[regional endpoint table](https://docs.aws.amazon.com/general/latest/gr/s3.html#s3_website_region_endpoints)
and [website endpoint guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html)
support the 34 explicitly enumerated commercial-region website suffixes and
HTTP-only operation. REST/access-point endpoints, China and GovCloud are excluded.

Retain the V1 rule: status 404, both missing-bucket body indicators, exact AmazonS3
server header, and no conflicting key/website/permission error indicators. V2
bounds error-code tokens, requires an untruncated complete body, and explains
missing headers or conflicting indicators. A match with a provider CNAME is
potential only; bucket namespace, ownership and reuse protections are not tested.
The [AWS security discussion](https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/)
describes why namespace and resource configuration matter.

The old `API/ErrorResponses.html` link redirected to an API index during review;
the database now links the accessible `API_Error.html` definition.

## Vercel

The [domain configuration guide](https://vercel.com/docs/domains/working-with-domains/add-a-domain)
currently documents a per-project target under `vercel-dns-017.com`; add this
specific suffix alongside the existing `vercel-dns.com` and `vercel.app` rules.
Do not infer arbitrary numbered zones. The
[missing-deployment error page](https://vercel.com/docs/errors/deployment_not_found)
documents the code and status, including incorrect URLs and deleted deployments.

Retain the 404/code rule as suspicious only. V2 requires token boundaries and a
complete body. Generic not-found text and prefixed/suffixed lookalike codes do
not match. Domain access protections and resource ownership are not inspected.

## GitHub Pages

[Domain configuration](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site)
and [domain verification](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/verifying-your-custom-domain-for-github-pages)
describe DNS targets, disabled sites and protections against domain reuse.
Retain `github.io` DNS identification. The review did not establish a stable
official HTTP contract that distinguishes unclaimed resources from publication
or plan errors. Historical missing-site text in tests remains an unverified
candidate, not an active fingerprint. HTTP resource state remains unknown.

## Azure App Service

[Microsoft's dangling DNS guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover)
and [custom-domain troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/azure/app-service/connection-issues-with-ssl-or-tls/troubleshoot-custom-domain-issues-azure-app-service)
describe `azurewebsites.net`, verification IDs, binding errors and other causes
of unavailable custom domains. A domain-binding error does not establish an
unclaimed cloud resource. Retain DNS-only detection; no generic Azure 404 or 403
rule is activated. Tests explicitly retain unknown results for these responses.

## Heroku

The [custom-domain documentation](https://devcenter.heroku.com/articles/custom-domains),
[domain troubleshooting](https://help.heroku.com/DRD4AWY7/why-don-t-i-see-my-site-when-i-access-my-custom-domain),
[error-page guide](https://devcenter.heroku.com/articles/error-pages) and
[error-code guide](https://devcenter.heroku.com/articles/error-codes#h31-misdirected-request)
describe domain targets, routing errors and different platform behavior.

The guide links the published
[no-such-app template](https://www.herokucdn.com/error-pages/no-such-app.html).
This static asset was retrieved successfully (HTTP 200) and its title/message
reviewed. That asset response does not establish a current router's status code,
headers, resource state or claimability. Retain DNS-only detection for
`herokudns.com` and `herokuapp.com`. Synthetic template text with a test 404 is
deliberately expected to remain unknown; that status is not a live router observation.

## Netlify

[External DNS configuration](https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/)
documents `netlify.app` targets and the exact apex load-balancer hostname; add
`apex-loadbalancer.netlify.com` as an exact match without treating all `netlify.com`
hosts as hosting targets. The
[verification update](https://www.netlify.com/changelog/enhanced-security-with-domain-dns-verification/)
and [troubleshooting guide](https://docs.netlify.com/manage/domains/troubleshooting-tips/)
provide protection/configuration context. No reliable distinct unclaimed-resource
HTTP contract was established. Retain DNS-only detection; generic missing-site
responses remain unknown.

## Fixtures and test interpretation

[`tests/fixtures/provider_cases.json`](../tests/fixtures/provider_cases.json)
contains three scenarios for each provider: provider-present, negative and
ambiguous. They are small synthetic examples, not full copied pages or captured
live responses. Source URLs and notes travel with each scenario.

For S3/Vercel, provider-present cases exercise the positive HTTP rule; negative
cases use healthy content; ambiguous cases exercise conflicting indicators or
truncation. For the four DNS-only providers, a positive DNS match deliberately
has no positive HTTP expectation: all three HTTP cases remain unknown. Candidate
messages or statuses in these fixtures must not be promoted to active rules
without a separate current behavior review.

Additional tests cover generic errors, missing/duplicate headers, code lookalikes,
redirects, experimental caps, DNS attribution changes and malformed rule files.
These tests validate implementation behavior and false-positive guards; they do
not measure sensitivity, precision or exploitability on live deployments.
