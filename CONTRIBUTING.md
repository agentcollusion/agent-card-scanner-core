# Contributing

Bug reports and focused pull requests are welcome. This repository maintains the single-card CLI and library; proposals for hosted infrastructure or ecosystem datasets are outside its current scope.

Use Node.js 22 or newer. No dependency installation is required:

```sh
npm run check
```

Use fictional cards and locally generated test keys. Transport tests must use injected fixtures, with no requests to real agents. Do not commit real cards, credentials, private keys, scans, or personal data.

Describe the affected input, expected and actual behavior, and the relevant CLI output with sensitive values removed. Include a regression test for changed parsing, signature, network, or exit-policy behavior. Preserve stable rule IDs and document changes to the report schema or inspection policy.

Pull requests run the Node.js 22/24 offline test and package checks. Keep changes focused and update the CLI contract when behavior changes. Contributions are provided under this repository's Apache-2.0 license.

For suspected vulnerabilities, use [SECURITY.md](SECURITY.md) rather than a public issue.
