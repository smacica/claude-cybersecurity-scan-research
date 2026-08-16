## Engagement context

This is an authorized defensive security assessment of the EatHub web
application (an Express/SQLite recipe-sharing API), conducted with the
application owner's consent as part of hardening the codebase before release.

Every request an agent makes goes to a disposable instance of the application
running on loopback inside this sandbox, seeded with synthetic fixture data
(three fictional users, two sample recipes). No production system, no real user
data, and no third-party service is involved: Google OAuth, SMTP, and the Gemini
integration are all unconfigured and degrade to disabled.

Findings are collected for the application owner to remediate. Scope is the
application's own HTTP attack surface — authentication, session handling, the
recipe/comment/like data model, file uploads, and outbound-link construction.
Out of scope: the unconfigured third-party integrations, denial-of-service by
resource exhaustion, and anything requiring access outside this sandbox.
