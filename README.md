# PipeGuard

A Claude skill that audits Azure DevOps YAML pipelines for security, reliability and cost issues, and returns a prioritized report with the corrected YAML for each finding.

## What it checks

25 rules in three groups:

- **Security (PG-S)**: plain-text secrets, script injection through parameters and variables, exposed `System.AccessToken`, production deployments with no approval gate, unpinned external code, fork pull requests with access to secrets, and more.
- **Reliability (PG-R)**: missing timeouts, unversioned tasks, deployments with no rollback, steps that cannot be re-run safely.
- **Cost and speed (PG-C)**: missing caches, full clones, jobs that could run in parallel.

The full list is in [`pipeguard/SKILL.md`](pipeguard/SKILL.md).

## Example

[`examples/vulnerable-pipeline.yml`](examples/vulnerable-pipeline.yml) is a deliberately flawed pipeline. [`examples/sample-report.md`](examples/sample-report.md) shows the report PipeGuard produces for it: 8 findings, each with the offending lines, the risk, and the fix.

## Install

**Claude Code**: copy the `pipeguard` folder into your skills directory.

```bash
git clone https://github.com/abirayedtn-source/pipeguard.git
cp -r pipeguard/pipeguard ~/.claude/skills/
```

To share it with a team, copy it into `.claude/skills/` at the root of the repository instead.

**Claude app**: zip the `pipeguard` folder and upload it as a skill in your Claude settings.

## Use

Ask Claude to audit a pipeline:

> Audit azure-pipelines.yml with PipeGuard

> Scan all the pipelines in this repo and give me the top five risks

You can also paste a pipeline directly into the conversation. PipeGuard only reports; it edits files when you ask it to apply a fix.

## Limits

- PipeGuard reads YAML. Settings that live in Azure DevOps (environment approvals, branch policies, service connection scope, variable group contents) are listed in the report as items to check by hand.
- Templates stored in other repositories are not audited unless you provide them.
- It is a review aid, not a replacement for a security audit.

## Contributing

Rule ideas and false positives are welcome: open an issue with the smallest pipeline snippet that shows the problem. Remove secrets and internal names first.

## License

[MIT](LICENSE)
