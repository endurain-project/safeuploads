# Security policy

## Supported versions

Security fixes are released against the latest published version only; there
are no maintained release branches. Upgrading to the current release is the
supported way to receive a fix.

| Version | Supported |
|---|---|
| `2.0.x` | Yes |
| `< 2.0` | No |

## Scope

In scope: anything in the `safeuploads` package. That includes the filename
and extension validators, archive and image bomb detection, the ZIP and gzip
inspectors, the XML parsing behind activity files, the resource monitor, and
any way a crafted upload could bypass a check, exhaust the host, or corrupt or
expose a host application's data through safeuploads' own code.

Out of scope: vulnerabilities in an application that *uses* safeuploads but
stem from its own code or configuration — for example allow-listing an
executable extension through `SecurityLimits`, serving an accepted upload back
inline from the document root, or storing a file under the client-supplied
name. Report those to that application's maintainers.

Vulnerabilities in a dependency should be reported upstream first. If
safeuploads' use of it makes the impact materially worse, report that here too.

## Reporting a vulnerability

1. **Do not** open a public issue.
2. Email <joao@endurain.com> with the details.
3. Include:
   - steps to reproduce;
   - the affected version;
   - potential impact;
   - any suggested fix, if you have one.
4. You will get an acknowledgement when possible.

Please include as much detail as you can — a sample payload and the
configuration it was validated under are what make a report actionable rather
than a starting point for investigation.

## What to expect

This project is maintained by one person in their spare time, so response times
vary. A fix will be released as soon as it is ready, and the advisory will
credit you unless you would rather stay anonymous.

Thank you for helping keep this project secure.
