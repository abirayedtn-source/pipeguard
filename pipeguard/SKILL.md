---
name: pipeguard
description: Audit Azure DevOps YAML pipelines for security, reliability and cost issues and produce a prioritized report with fixes. Use when asked to scan, review, audit or harden an azure-pipelines file.
---

# PipeGuard: Azure DevOps pipeline audit

PipeGuard reviews Azure DevOps YAML pipelines the way a senior DevOps engineer would in a security review: it finds concrete problems, ranks them, and proposes the exact YAML change that fixes each one.

## 1. Collect the pipeline files

- If the user pasted or attached YAML, audit that.
- If working in a repository, find every pipeline file: `azure-pipelines*.yml`, `*.azure-pipelines.yml`, anything under `.azuredevops/`, `.pipelines/`, `pipelines/`, `build/`, plus every file referenced by `template:` or `extends:`.
- Follow local templates and audit them too. A finding in a template is reported once, with the list of pipelines that include it.
- For templates in another repository (`resources.repositories`), do not guess their content. Report them as "not audited" and check only how they are referenced (see PG-S06).

Read each file completely before reporting. Never report a line number you have not seen.

## 2. Apply the rules

Each finding gets a rule ID, a severity (Critical, High, Medium, Low) and a file and line.

### Security

| ID | Check | Default severity |
|---|---|---|
| PG-S01 | Secret in plain text: passwords, tokens, connection strings, keys or SAS URLs in `variables:`, script bodies or task inputs | Critical |
| PG-S02 | Script injection: `${{ parameters.x }}` or `$(var)` expanded directly inside an inline `script`, `bash`, `pwsh` or `powershell` body when the value can be set by a user (queue-time variable, free-text parameter, branch name, PR title, commit message). Fix by passing it through `env:` and reading the environment variable | High |
| PG-S03 | Secret printed or leaked: `echo` of a secret, `set -x` or `Set-PSDebug -Trace` around secret usage, `system.debug: true` committed, secrets passed as command-line arguments, secrets written to artifacts or logs | High |
| PG-S04 | `System.AccessToken` exposed more than needed: mapped at job level instead of on the single step that needs it, or `persistCredentials: true` on checkout with later steps running third-party code | High |
| PG-S05 | Production deployment with no gate: a job deploying to production that is not a `deployment` job bound to an `environment`, so no approvals or checks can apply | High |
| PG-S06 | Unpinned external code: repository resources without a `ref` pinned to a tag or commit, container images on `latest` or with no tag, `curl ... | bash` or `iwr ... | iex`, package installs with no version or on `@latest` | High |
| PG-S07 | Pull request builds from forks with access to secrets or running on self-hosted agents | High |
| PG-S08 | Free-text parameters with no `values:` allow-list where the value selects an environment, subscription, service connection or script path | Medium |
| PG-S09 | Service connection too broad for the job: the same connection used for dev and prod, or a subscription-wide connection used for a single resource group task | Medium |
| PG-S10 | Security step that cannot fail the build: `continueOnError: true` or `condition: always()` on scanning, test or signing steps | Medium |
| PG-S11 | Secrets kept in pipeline variables or plain variable groups where a Key Vault linked variable group or the `AzureKeyVault` task would fit | Low |
| PG-S12 | Pipeline not built on a protected `extends` template in a repository where other pipelines are | Low |
| PG-S13 | Pipeline pushes commits straight to the branch it ran from, which can bypass pull requests and branch policies on protected branches | Medium |

### Reliability

| ID | Check | Default severity |
|---|---|---|
| PG-R01 | No `timeoutInMinutes` on jobs that can hang (deployments, integration tests, manual waits, CLIs that may prompt) | Medium |
| PG-R02 | Task without a major version (`Task` instead of `Task@2`) or a deprecated task version | Medium |
| PG-R03 | Deployment with no rollback path or health check after the deploy step | Medium |
| PG-R04 | `trigger` or `pr` missing or implicit, so every branch builds, or `batch` missing on a busy branch | Low |
| PG-R05 | Conditions that silently skip stages (`condition: succeeded()` missing after a custom condition, wrong `dependsOn`) | Medium |
| PG-R06 | Hard-coded values duplicated across stages that should be parameters or a template | Low |
| PG-R07 | Irreversible external side effect (resource created in a third-party system, release published, record registered) followed by a step that can fail, with nothing that makes a re-run safe or lets the result be recovered | Medium |
| PG-R08 | `git add .` or `git add -A` in a pipeline that commits, which stages the whole workspace instead of the files the pipeline produced | Low |

### Cost and speed

| ID | Check | Default severity |
|---|---|---|
| PG-C01 | No dependency cache (`Cache@2`) for npm, NuGet, pip, Maven or Gradle restores | Low |
| PG-C02 | Full clone where shallow is enough (`fetchDepth` unset or 0 without a need for history) | Low |
| PG-C03 | Independent jobs run in sequence instead of in parallel | Low |
| PG-C04 | Heavy stages running on every PR that could be limited with path filters | Low |

Adjust severity to context and say why: a plain-text secret in a pipeline for a public repository is worse than in a private sandbox.

## 3. Verify before reporting

- Every finding must quote the offending lines. No quote, no finding.
- Do not flag `$(var)` as a leaked secret just because of its name; flag it when the value is visible or when it is printed.
- Do not flag macro variables in task inputs as injection; PG-S02 is about inline script bodies.
- If something depends on settings outside the YAML (environment approvals, branch policies, service connection scope, variable group contents), do not assume. List it under "To check in Azure DevOps" with the exact place to look.
- If the pipeline is clean on a category, say so in one line rather than inventing low-value findings.

## 4. Report format

Write the report in the user's language.

1. **Summary**: one sentence verdict, then the count of findings per severity.
2. **Findings**, most severe first. For each:
   - `[Severity] PG-XXX: short title` and `file:line`
   - The offending lines, quoted
   - Why it matters, in one or two sentences, with the concrete attack or failure
   - The fix, as corrected YAML ready to paste
3. **To check in Azure DevOps**: settings that cannot be seen from the YAML.
4. **Not audited**: external templates and anything that could not be read.

Keep it short. A reader should be able to fix the top three findings in ten minutes.

## 5. Applying fixes

Only edit pipeline files when the user asks. When they do:

- Fix one finding per change so each can be reviewed and reverted on its own.
- Never invent secret values, service connection names or environment names; use a clearly marked placeholder and say what must be filled in.
- When a plain-text secret is found, the fix is not only removing it: tell the user the secret must be rotated, because it remains in the Git history.
