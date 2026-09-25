# Agent Card Scanner Core

[![test](https://github.com/agentcollusion/agent-card-scanner-core/actions/workflows/test.yml/badge.svg)](https://github.com/agentcollusion/agent-card-scanner-core/actions/workflows/test.yml)
[日本語](README.ja.md) · [CLI contract](docs/cli.md) · [Web inspector](https://scan.agentcollusion.ai)

Inspect an A2A Agent Card, verify its signatures, and get findings with evidence and remediation. This is the **Apache-2.0 open-source CLI and Node.js library** extracted from Agent Card Scanner. Node.js 22+, zero runtime or development dependencies, no API key, no telemetry.

## Quick start

Run the fictional offline example without installing any packages:

```sh
git clone --branch v0.5.0 https://github.com/agentcollusion/agent-card-scanner-core.git
cd agent-card-scanner-core
node src/cli.mjs verify examples/unsigned-card.json --url https://agent.example.com/card.json --format text
```

The example passes the default policy with advisory findings for an unsigned card and undeclared authentication. `PASS` means the selected inspection policy passed; it does not establish runtime safety or operator identity.

Install the CLI directly from the GitHub release tag:

```sh
npm install -g git+https://github.com/agentcollusion/agent-card-scanner-core.git#v0.5.0
agent-card-scanner --help
```

This package is distributed through GitHub. There is no npm registry publication. The package name is `agent-card-scanner-core`; the executable remains `agent-card-scanner`. It uses the same executable name as the earlier site-distributed CLI, so installing both globally replaces the shared command.

## Basic features

- Inspect a local JSON card offline or retrieve a card from a public HTTPS URL.
- Check a documented subset of core fields, interface URLs, and authentication declarations.
- Verify supported JWS signatures using caller-selected public JWKS or explicitly enabled same-origin key discovery.
- Produce JSON or readable text with stable rule IDs, evidence, remediation, limitations, and a configurable CI exit policy.
- Import the same inspection functions into another Node.js application.

```sh
# Local file: no network requests by default
agent-card-scanner verify agent-card.json --url https://your-agent.example/card.json --format text

# Read a generated card from a pipeline without creating a temporary file
cat agent-card.json | agent-card-scanner verify - --url https://your-agent.example/card.json --format text

# Require a signature verified with your selected public keys
agent-card-scanner verify agent-card.json --url https://your-agent.example/card.json --jwks public-jwks.json --require-signature

# Inspect an already-published card; no agent tasks are invoked
agent-card-scanner check https://your-agent.example/card.json --format json

# Use a stricter policy in CI
agent-card-scanner verify agent-card.json --url https://your-agent.example/card.json --fail-on medium
```

Replace the fictional domains with the card's actual publication URL. `check host.example` discovers the current well-known path, then the legacy path. An explicit URL with a path is checked directly.

| Exit code | Meaning |
| --- | --- |
| 0 | Inspection complete; selected policy passed |
| 1 | Inspection complete; selected policy failed |
| 2 | Invalid input or command usage |
| 3 | Operation incomplete, such as an unreadable file or failed retrieval |

Advisory findings never fail the threshold. `--require-signature` is an independent requirement. JSON is the default output; operational errors are a single JSON object on stderr.

`verify -` reads standard input with the same 512 KiB byte limit, strict UTF-8 decoding and duplicate-key rejection as file input. On PowerShell, use `Get-Content -Raw -Encoding utf8 agent-card.json` instead of `cat`. Interface findings include a JSON pointer such as `/supportedInterfaces/0/url`, also shown as `At:` in text output.

## Library

Install the same GitHub URL without `-g`, then:

```js
import { readFileSync } from 'node:fs';
import { inspectCard, renderInspection } from 'agent-card-scanner-core';

const card = JSON.parse(readFileSync('agent-card.json', 'utf8'));
const publicJwks = JSON.parse(readFileSync('public-jwks.json', 'utf8'));
const report = await inspectCard(card, {
  cardUrl: 'https://your-agent.example/card.json',
  trustedKeys: publicJwks.keys,
  localOnly: true,
  requireSignature: true,
});
console.log(renderInspection(report));
```

`inspectPublished` is also exported for public URL retrieval. See the [CLI and inspection contract](docs/cli.md) and [report schema](schemas/inspection.schema.json).

## Scope and limits

This repository contains single-card inspection, signature verification, the CLI/library, tests, schema, and fictional examples. Hosted Web/API infrastructure, deployment configuration, research batch scanning, clustering, collected datasets, and internal planning materials are outside this core release. The [hosted Web inspector](https://scan.agentcollusion.ai) is available separately.

Local `verify` is offline unless `--network` is supplied. Public retrieval checks and pins DNS addresses, retains TLS verification, bounds redirects/body size/time, and restricts remote keys to the card's exact HTTPS origin. Local JWKS does not silently fall back to publisher-selected keys.

Coverage is partial, not a complete A2A conformance suite. A valid signature establishes integrity with the selected key under the documented profile; it does not establish identity, authorization, key revocation status, runtime safety, or absence of collusion. Reports can contain publisher-provided text and endpoint paths; review them before sharing. Independent SDK interoperability validation remains ongoing.

## Development

```sh
npm run check
```

No dependency installation is required. This runs the regression suite and packs/installs the actual CLI archive offline, checking its contents and library exports. CI runs on Node.js 22 and 24 in Linux containers with networking disabled during tests. Transport tests use fixtures rather than live services.

See [CONTRIBUTING.md](CONTRIBUTING.md) for changes and [SECURITY.md](SECURITY.md) for private vulnerability reports.

## License

[Apache License 2.0](LICENSE), copyright 2026 AgentCollusion. See [NOTICE](NOTICE). Maintained by [AgentCollusion](https://agentcollusion.ai).

## Compare an Agent Card update

```sh
agent-card-scanner compare before.json after.json --format text
```

Version 0.5.0 adds an offline release checklist for changes in skill IDs, interfaces, authentication, media types and capabilities. Exit 1 requests review; it is not a runtime compatibility verdict. Use `compareCardJson(beforeText, afterText)` from the library for the same strict JSON comparison. Read the [profile and limits](docs/cli.md#compare-card-updates-locally). The hosted [comparison page](https://scan.agentcollusion.ai/compare) processes both cards in your browser.
