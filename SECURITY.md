# Security policy

Security fixes target the latest released version of Agent Card Scanner Core. Earlier releases should be upgraded; no long-term support schedule is promised.

Please report suspected vulnerabilities privately to **contact@agentcollusion.ai** with the subject `Agent Card Scanner Core security report`. Include the affected version, relevant code path, expected and actual behavior, and a minimal reproduction using fictional inputs. Do not include live credentials or other people's data. Please avoid public disclosure until maintainers have had an opportunity to investigate.

Useful reports include false-positive signature acceptance, unintended network access during offline verification, network-policy bypasses, and sensitive input disclosure. Use source review or isolated local fixtures; do not test against the hosted service or third-party agents without separate authorization.

This is a static card inspector. A valid signature is not a guarantee of operator identity, authorization, runtime safety, key revocation status, or absence of collusion. See [the documented policy and limits](docs/cli.md).
