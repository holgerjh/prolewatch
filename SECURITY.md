# Security Policy

Prolewatch is experimental security software and has not received an
independent security audit. Reports that could affect its inspection,
containment, privilege, artifact-integrity, or fail-closed guarantees are
especially important.

## Supported versions

Security fixes are made against the current default branch and the latest
released version. Older installations may no longer match the documented
security boundary and should be updated before they are relied upon. Reports
against older versions are still useful when the behavior also reproduces on
the current code.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/holgerjh/prolewatch/security/advisories/new)
to contact the maintainer privately. If the private reporting form is
unavailable, open a minimal public issue requesting a private contact channel
without including vulnerability details.

Include, when available:

- the affected version or commit;
- the required privileges and trust boundary;
- a minimal reproduction or concrete attack path;
- the expected and observed behavior; and
- any suggested mitigation.

Do not include credentials or data from other people. Do not execute a
destructive proof of concept, attempt persistence, or test systems you do not
own or have explicit permission to assess. A reasoned reproduction is welcome
when demonstrating the impact would require unsafe root-side effects.

The maintainer will validate the report, coordinate remediation, and discuss
disclosure through the private advisory. No response or remediation deadline is
currently guaranteed.

## Open findings

- Assessment date: 2026-08-12
- Baseline commit: `a627a74bcc08e424048a58c2591a96358b16c354`

No known non-remediated findings remain from this assessment. Confirmed open
findings will be listed in this section; remediated entries remain available in
Git history.
