# Synthetic response and TLS fixtures

`responses.json` contains synthetic bodies, statuses and headers exercising the
existing bundled S3 and Vercel rules. Generic and healthy responses add no new
provider indicators. The ambiguous S3 fixture deliberately combines a positive
indicator and the existing negative key indicator. Padding and mismatched
Content-Length simulate bounded inspection and incomplete HTTP framing.

TLS files:

- `lab-ca.pem`: public certificate for a dedicated fixture CA.
- `server-cert.pem`: server certificate with SANs `*.dangl3.test` and `dangl3.test`.
- `server-key.pem`: deliberately public, lab-only private key for that certificate.

These files are committed so running the lab requires no certificate-generation
tool or Internet connection. The CA private key used to sign the fixture was
discarded. No production credentials are present. The server certificate expires
on 2036-10-20; it was generated for this lab on 2026-10-23 using OpenSSL.

The CA is loaded only into the local transport's SSL context. It must never be
installed into the OS/browser trust store, and the test private key must never
be used outside this isolated lab. Regenerating/replacing all three fixtures is
a maintenance operation; the runner must fail certificate verification rather
than work around expiration or hostname errors.
