# Security reporting

Report a vulnerability privately through GitHub's [private vulnerability
reporting form](https://github.com/StatPan/datapan-health/security/advisories/new).
The form is the only supported channel for sensitive reports in this
repository; do not send credentials, provider URLs, response data, or exploit
details in a public GitHub issue.

Security support currently covers the maintained `main` branch. Historical
revisions do not receive a separate security-support commitment. We target an
initial acknowledgement within seven calendar days. After a report is
triaged, we will coordinate a fix and disclosure timing privately with the
reporter when contact information is available.

Maintainers can revalidate that GitHub still exposes this private route with
`make security-reporting-check`; the check reads the repository setting and
does not create a report.

Public issues remain appropriate for non-sensitive bugs and documentation
problems only. Remove credentials, provider URLs, response data, and any
exploit details from those reports.
