# PipeGuard

A Claude skill that audits Azure DevOps YAML pipelines for security, reliability and cost issues, and returns a prioritized report with the corrected YAML for each finding.

## What it checks

29 rules in three groups:

- **Security (PG-S)**: plain-text secrets, script injection through parameters and variables, exposed `System.AccessToken`, production deployments with no approval gate, unpinned external code, untrusted pull requests reaching secrets or self-hosted agents, deploy steps that also run on pull requests, and more.
- **Reliability (PG-R)**: unversioned tasks, deployments with no rollback, steps that cannot be re-run safely, retired agent images.
- **Cost and speed (PG-C)**: missing caches, full clones, jobs that could run in parallel.

The full list is in [`pipeguard/SKILL.md`](pipeguard/SKILL.md).

## Example

[`examples/vulnerable-pipeline.yml`](examples/vulnerable-pipeline.yml) is a deliberately flawed pipeline. [`examples/sample-report.md`](examples/sample-report.md) shows the report PipeGuard produces for it: each finding comes with the offending lines, the risk, and the fix.

## Run it without Claude

The skill ships a scanner, `pipeguard/scripts/pipeguard_scan.py`, that applies 19 of the 29 rules with fixed logic. Same input, same output, exact line numbers. It needs Python 3.8+ and PyYAML.

```bash
python pipeguard/scripts/pipeguard_scan.py path/to/repo --hosting github
```

```
PipeGuard 0.2.0: 1 file(s) scanned
  1 critical, 6 high, 2 medium, 0 low, 2 housekeeping

FINDINGS
  [CRITICAL] PG-S01 Secret in plain text  (examples/vulnerable-pipeline.yml:12)
      > storageKey: 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg=='  # fake value for the demo
      `storageKey` is set to a literal value in the YAML.
      Fix: Move it to a Key Vault linked variable group, then rotate it: it stays in the Git history.
  ...
```

| Option | Use |
|---|---|
| `--format text\|json\|sarif` | Human report, JSON for tooling, or SARIF 2.1.0 for code scanning views |
| `--fail-on low\|medium\|high\|critical\|none` | Exit with code 1 at or above this level (default `high`). Housekeeping items never fail a build |
| `--hosting github\|azure-repos\|unknown` | Where the repository lives. Decides whether a deploy step with no pull request condition is a finding or an item to check |
| `--output FILE` | Write the report to a file |

### As a gate in your own pipeline

Copy `pipeguard_scan.py` into your repository (one file, MIT licence) and add a step:

```yaml
- script: |
    python -m pip install pyyaml==6.0.3
    python tools/pipeguard_scan.py . --hosting azure-repos --fail-on high
  displayName: PipeGuard
```

The build fails when a High or Critical finding appears in any pipeline file of the repository.

### What the scanner does not do

It matches patterns; it does not understand intent. Ten rules need reading and are left to Claude or to a reviewer, and the scanner lists them at the end of every report. It was compared against a manual review of 45 public pipelines: it found the same pipelines for secrets on the command line, disabled security scans, retired images and self-hosted pools, and it missed cases such as a password written to a file and then printed. Use it as a first pass and a regression gate, with the skill for the full review.

### Tests

```bash
python -m unittest discover -s tests
```

`tests/fixtures/` holds one failing and one passing pipeline per scanner rule.

## How the rules were tuned

The rules were checked against 45 public Azure DevOps pipelines sampled from GitHub. That review reshaped several of them: most real findings did not use the obvious keyword (a scanner switched off with its own option rather than `continueOnError`, a remote script run through `bash <(curl ...)` rather than `curl | bash`), and two rules fired on almost every pipeline and are now grouped as housekeeping.

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
