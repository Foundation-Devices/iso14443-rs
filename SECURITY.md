# Security Policy

## Reporting a vulnerability

Please do not open a public issue or discussion for a suspected security vulnerability.

Report vulnerabilities privately through Foundation's responsible disclosure form:

https://foundation.xyz/responsible-disclosure/

For encrypted email, contact `security@foundation.xyz` using Foundation's security disclosure PGP key:

https://foundation.xyz/pgp-email/

Include, when possible:

- the affected repository, product, version, release, or commit;
- the vulnerability's security impact;
- clear reproduction steps or a minimal proof of concept;
- relevant logs, screenshots, or traces with secrets and personal data removed;
- any suggested mitigation or fix.

Do not include seed phrases, private keys, wallet passwords, API tokens, or customer data.

## Disclosure process

Please allow Foundation reasonable time to investigate and remediate the issue before public disclosure. Foundation's current scope, eligibility, disclosure requirements, and bounty terms are defined by the responsible disclosure policy linked above.

## Continuous integration

CI builds, lints and tests this crate on GitHub-hosted runners. No job publishes, deploys, signs, or writes to the repository, and none uses a long-lived secret.

Because action code runs before the build and can reach the automatically provided `GITHUB_TOKEN`, the workflow keeps that trust boundary narrow:

- every external action is pinned to a full commit SHA, with the release it names in a trailing comment — a tag or branch can be repointed at other code by whoever controls the upstream repository, a commit SHA cannot;
- the workflow declares `permissions: contents: read`, so the token's authority is set in version control rather than inherited from repository or organization defaults;
- checkout runs with `persist-credentials: false`, leaving no token in the working tree for later steps to pick up;
- Dependabot proposes SHA bumps as reviewable pull requests, so pinning does not mean staying on unpatched action code;
- a `pinning` job fails the build if any `uses:` reference loses its commit SHA.

These are backed by repository settings, which an owner maintains: the default workflow token permission is read-only, and workflow runs on pull requests from forks require maintainer approval.

## Supported versions

Supported versions vary by project. Include the affected version or commit in your report. Foundation will confirm whether that version is currently supported and whether remediation will be applied to other maintained releases.
