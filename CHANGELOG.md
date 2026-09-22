# Changelog

## 0.4.0 — 2026-09-23

- Accept piped card JSON with `verify -`, bounded to 512 KiB and decoded with the same strict UTF-8/JSON checks as files.
- Reject malformed, empty or ambiguous interface URLs with `AC-URL-001`; recognize uppercase HTTPS schemes correctly.
- Include exact JSON pointers for each interface finding and show them in text output; report malformed optional interface declarations instead of silently dropping them.
- Apply consistent caller-public-key validation to CLI and library entry points, before public retrieval, and redact uppercase HTTP(S) URLs in report text.
- Return usage errors for unknown commands that match JavaScript prototype property names.
- Retain report schema 1.0 and signature payload processing; advance inspection policy to `same-origin-v1.0.1-2026-09-r2`. See the migration notes in the CLI contract.

## 0.3.1 — 2026-09-23

First standalone open-source core release, extracted from Agent Card Scanner 0.3.0.

- Publish local/public single-card inspection, signature verification, evidence and remediation, configurable CI exits, and Node.js library exports under Apache-2.0.
- Retain report schema 1.0 and the `same-origin-v1.0.1-2026-09` verification policy.
- Package as `agent-card-scanner-core`, retaining the `agent-card-scanner` executable and report tool name.
- Exclude research batch commands, clustering, hosted Web/API infrastructure, deployment configuration, collected data, and internal documents.
- Add English/Japanese getting-started guides, contribution/security guidance, and offline Node.js 22/24 CI with actual package-install validation.

The site-distributed 0.3.0 package and hosted Web application are separate distributions. Their version numbers and available commands can differ from this core package.
