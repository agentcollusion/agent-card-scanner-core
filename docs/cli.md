# CLI and inspection contract

Core version: 0.3.1. Report schema: 1.0. Policy: `same-origin-v1.0.1-2026-09`.

## Commands

```sh
# No network, including key discovery
agent-card-scanner verify agent-card.json --url https://agent.example/card.json --format text

# Keys chosen by the caller, never replaced by an embedded jku
agent-card-scanner verify agent-card.json --url https://agent.example/card.json --jwks public-jwks.json --require-signature

# Explicit opt-in to same-origin key retrieval
agent-card-scanner verify agent-card.json --url https://agent.example/card.json --network

# Published host: tries the current well-known path, then the legacy path
agent-card-scanner check agent.example --format text

# An explicit URL with a path/query is inspected exactly, regardless of extension
agent-card-scanner check https://agent.example/agents/quote/card --format json

# Review a public partner card with keys selected by your team
agent-card-scanner check https://partner.example/card --jwks partner-public-jwks.json --require-signature
```

Use `node src/cli.mjs` from a checkout, or install the tagged package from GitHub as described in the README. Node.js 22+; no runtime dependencies or API keys. All diagnostics and remediation text are English. `--help` and `--version` are available without network access.

`check` supports your deployed agents and already-public third-party agents without enrollment or proof of domain ownership. It retrieves card/key documents only, without calling declared agent tasks or authentication endpoints. Re-run the command after deployment or key rotation; each run is a point-in-time observation. There is no built-in scheduler, alert service or automatic comparison of runs.

Single-card options: `--format json|text` (default `json`), `--fail-on critical|high|medium|low|none` (default `high`), `--require-signature`, `--jwks <file>`. Local `verify` also accepts `--url` (required) and `--network`.

Flags may precede or follow the target after the command. Unknown flags, repeats, missing values, extra targets and invalid enum/range values are errors. Prefix a filename beginning with `-` with `./`.

## Exit and output semantics

| Code | Meaning | Output |
| --- | --- | --- |
| 0 | Inspection completed and the selected policy passed | One report on stdout |
| 1 | Inspection completed and the selected policy failed | One report on stdout |
| 2 | Invalid CLI input, invalid local card/JSON, or invalid public JWKS | One JSON error on stderr; empty stdout |
| 3 | Operation incomplete: unreadable file, fetch failure, inaccessible/non-card remote response | One JSON error on stderr; empty stdout |

Expected errors never print a stack or the raw input. JSON is the default even when piped. `--format text` is for people; do not parse its prose. A pass means only that this run met the selected threshold. `--fail-on none` disables finding-based failure. `--require-signature` independently requires at least one accepted verification. A malformed extra signature can fail the finding threshold even when another signature verifies; the report identifies each signature by index.

Findings classified `advisory` do not fail a threshold. `spec` means a documented standard-derived check; `policy` means this scanner's chosen verification/security policy. Severity does not certify exploitability. This release checks core field presence/types and selected card declarations, not the full A2A schema or all cross-field constraints.

## JSON report

The schema is in [../schemas/inspection.schema.json](../schemas/inspection.schema.json). Top-level fields:

| Field | Purpose |
| --- | --- |
| `schemaVersion` | Report contract version; additive fields may appear within a major version |
| `tool` | Name and exact tool version |
| `policy` | Policy version, failure threshold, signature requirement and key-resolution mode |
| `target` | Redacted publication URL, display name, shape generation, SHA-256 of the complete input card serialized with JCS |
| `status` / `decision` | Completed inspection versus its pass/fail outcome |
| `blockingRuleIds` / `signatureRequiredFailed` | Why the selected policy failed |
| `signatures` | Independent `unsigned`, `valid`, `invalid`, `rejected`, or `unresolved` results; accepted key thumbprint/source when available; optional profile-mismatch `diagnostic` |
| `findings` | Stable ID, severity, category, evidence, remediation and limitation; signature findings include a JSON pointer |
| `coverage` / `limitation` | What was checked, canonicalization profile, and explicit untested areas |
| `discovery` | Present for a published-card check: source, attempt count and `retrievedAt` (UTC receipt time of the card response; key retrieval may finish later) |

Consumers must ignore unknown additive fields. Do not derive identity from display names. Report URLs remove user information, query contents and fragments; they are not replay URLs. Reports can still contain sensitive publisher-supplied text, endpoint paths and key identifiers, so treat them as private artifacts unless reviewed. The input card and private keys are never included by default. There is no telemetry or automatic upload.

`target.url` is the final card URL after redirects and sets the origin for remote key lookup. `target.sha256` identifies the complete parsed card under JCS. Together with `discovery.retrievedAt`, these describe the inspected snapshot, not an expiry or a continuing assertion about the live service. Earlier schema 1.0 reports may omit the additive retrieval time; consumers must display unknown freshness rather than inventing a timestamp. A changed digest alone is not an actionable regression; compare policy versions and findings before drawing conclusions.

## Signature and key policy

- A2A v1 camelCase cards use field-presence/default rules based on upstream v1.0.1, then JCS. Required and explicitly optional defaults remain. Extension `params` and unknown JSON are retained. v0.x/other shapes use raw-card JCS with `signatures` excluded. Unknown future semantics and full proto reconstruction are not certified.
- If a v1 signature fails that profile but verifies over raw-card JCS with an already-selected compatible key, `diagnostic.code` is `RAW_JCS_ONLY`. This explains a serialization-profile mismatch; status remains `invalid`, `AC-SIG-001` remains blocking at the default threshold, and it cannot satisfy `--require-signature`. No additional key URLs or alternative trust sources are used. The diagnostic's nested key metadata is evidence for the alternative profile only, not an accepted key result.
- Supported key families: ES256/P-256, ES384/P-384, ES512/P-521, EdDSA or Ed25519 with Ed25519, and RS/PS256/384/512 with RSA 2048–8192 bits. Keys must agree with declared `alg`, `use`, and `key_ops` when present.
- At most eight signatures and 32 keys; strict base64url and protected-header JSON; unsupported `crit`, `b64`, embedded `jwk`, `x5u` and `x5c` are rejected. Policy-relevant unprotected fields and duplicate protected/unprotected members are rejected.
- With `--jwks`, only the supplied public keys are used, even if empty or unmatched. A cross-origin `jku` is still rejected under the chosen policy; callers must reconfigure the card or key publication rather than silently relax trust.
- Remote `jku` must share the card's exact HTTPS origin, including port. Every redirect retains that boundary. Sibling subdomains are distinct; the approximate domain table used for advisory host comparisons does not grant key trust.
- `valid` verifies integrity with the selected key; it does not prove that a named organization owns it. No independent expiration/revocation registry is consulted. Caller key governance remains necessary.

## Network bounds

Each retrieval has an 8-second total deadline including DNS, redirects and body; 512 KiB body cap; at most three redirects. The transport requests identity encoding and rejects compressed responses. It checks all DNS addresses, pins a checked IP in the HTTPS connection, retains TLS hostname verification, and does not use environment proxy settings. Only global/public addresses under a conservative policy are accepted; special-purpose and transition ranges are rejected. A multi-signature check can take longer than one retrieval budget.
