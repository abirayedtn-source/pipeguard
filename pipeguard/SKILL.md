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

Read each file completely before reporting. Never report a line number you have not seen. Keyword search alone is not enough: most real findings do not use the obvious keyword (see the notes under each table).

## 2. Apply the rules

Each finding gets a rule ID, a severity (Critical, High, Medium, Low) and a file and line.

### Start with the scanner

`scripts/pipeguard_scan.py` applies the mechanical part of the rules below and returns exact files and line numbers. When Python 3 and PyYAML are available, run it before reading:

```bash
python scripts/pipeguard_scan.py <file or folder> --format json --fail-on none --hosting <github|azure-repos|unknown>
```

Then use its output as a starting point, not as the report:

- Open every finding in its file and read the quoted line in context. Drop it if a known false positive applies (section 3), and adjust the severity to the context.
- Entries with `"housekeeping": true` go to the Housekeeping section. Entries under `checks` go to "To check in Azure DevOps" or "Not audited".
- The scanner covers 19 of the 29 rules. It does not judge PG-S09, PG-S11, PG-S12, PG-R03, PG-R05, PG-R06, PG-R07, PG-C02, PG-C03 or PG-C04, and it only lists self-hosted pools for PG-S07. It also misses what needs understanding rather than matching: a secret written to a file and then printed, a mutable `latest` tag deployed through a variable, a deploy script with an unusual name. Read the files for those.
- A script whose name suggests a deployment (`deploy.sh`, `npm run release`) is reported as Medium because the scanner is guessing. Confirm what the script does before keeping it.

If the scanner cannot run, say so in one line and apply every rule by reading. Do not install packages without asking.

### Security

| ID | Check | Default severity |
|---|---|---|
| PG-S01 | Secret in plain text: passwords, tokens, connection strings, keys or SAS URLs in `variables:`, script bodies or task inputs | Critical |
| PG-S02 | Script injection: `${{ parameters.x }}` or `$(var)` expanded directly inside an inline `script`, `bash`, `pwsh` or `powershell` body when the value can be set by a user (queue-time variable, free-text parameter, branch or tag name, PR title, commit message). Fix by passing it through `env:` and reading the environment variable | High |
| PG-S03 | Secret exposed on the way to a tool: a secret macro written into an inline script or a script's `arguments:` (`-k $(apiKey)`, `--secret "$(x)"`), a secret written to a file that is then printed or published, `set -x` or `Set-PSDebug -Trace` around secret usage, `system.debug: true` committed. Fix by mapping the secret in `env:` on that step only | High |
| PG-S04 | `System.AccessToken` exposed more than needed: mapped at job level instead of on the single step that needs it, or `persistCredentials: true` on checkout with later steps running third-party code | High |
| PG-S05 | Deployment or public release with no gate: a job that deploys to an environment or publishes a package, image or release, and is not a `deployment` job bound to an `environment`, so no approvals or checks can apply | High |
| PG-S06 | Unpinned external code, in any form (see the list below) | High |
| PG-S07 | Untrusted pull requests reaching sensitive resources: PR builds from forks with access to secrets, or a self-hosted agent pool used by a pipeline in a public repository | High |
| PG-S08 | Free-text parameters with no `values:` allow-list where the value selects an environment, subscription, service connection or script path | Medium |
| PG-S09 | Service connection too broad for the job: the same connection used for dev and prod, or a subscription-wide connection used for a single resource group task | Medium |
| PG-S10 | Security step that cannot fail the build, in any form (see the list below) | Medium |
| PG-S11 | Secrets kept in pipeline variables or plain variable groups where a Key Vault linked variable group or the `AzureKeyVault` task would fit | Low |
| PG-S12 | Pipeline not built on a protected `extends` template in a repository where other pipelines are | Low |
| PG-S13 | Pipeline pushes commits straight to the branch it ran from, which can bypass pull requests and branch policies on protected branches | Medium |
| PG-S14 | Deploy or publish step that also runs on pull request builds: no `condition` excluding `Build.Reason` `PullRequest` and no branch condition, in a pipeline where PR builds are on | High |
| PG-S15 | Production stage reachable from any branch: wildcard or feature-branch trigger flowing into a production stage, a `Manual` run accepted from any branch, or no branch condition at all on the stage | Medium |
| PG-S16 | `AzureKeyVault` task with `SecretsFilter: '*'`, which loads every secret in the vault into the job | Low |

**PG-S05, what counts as a gate.** A `deployment` job with an `environment` is a gate only if approvals or checks are configured on that environment, which the YAML does not show: list it under "To check in Azure DevOps". A `ManualValidation` task in an agentless job before the deploy stage is also a gate. Flag it as Medium when it has `onTimeout: 'resume'`, because the deployment then approves itself when nobody answers.

**PG-S06, forms to look for.**
- Remote script piped to a shell: `curl ... | bash`, `wget ... | sh`, `iwr ... | iex`, and process substitution `bash <(curl ...)`.
- Download then execute in two steps: `curl -O x.sh` followed by `./x.sh` or `sudo ./x.sh`; `Invoke-WebRequest -OutFile $f` followed by `& $f`. A URL pointing at a branch (`/master/`, `/main/`) is worse than one pointing at a version.
- `git clone` of another repository at its default branch, whose content is then built or deployed.
- Tools installed with no version or a floating one: `npm install -g x`, `pip install x`, `dotnet tool install x` (and `--prerelease`), `Install-Module x`, installer tasks set to `latest` or `*`, `@latest`.
- Container images on `latest` or with no tag, and deployments of a mutable `latest` tag.
- Repository resources without a `ref` pinned to a tag or commit.

Severity depends on what the code can reach: High when it runs in a job that holds deployment credentials, signing certificates or publish tokens; Low in a build-only job with no secrets.

**PG-S10, forms to look for.** `continueOnError: true` or `condition: always()` on a scanning, test or signing step, and the scanner's own switch that does the same thing under another name, such as `succeedOnFailures: true`, `ContinueOnVulnerablePackageScanError: true`, `failOnIssues: false`, an exit-code override, or `|| true` after the scan command. Do not flag `continueOnError` on steps that only publish test results or coverage, or on formatting checks.

**PG-S14, when PR builds are on.** For repositories hosted on GitHub or Bitbucket, PR builds run for every branch unless the YAML says `pr: none`. For Azure Repos, PR builds come from branch policies, which the YAML does not show. If the hosting is unknown, list the item under "To check in Azure DevOps" instead of reporting it as a finding.

### Reliability

| ID | Check | Default severity |
|---|---|---|
| PG-R01 | No `timeoutInMinutes` on jobs that can hang (deployments, integration tests, manual waits, CLIs that may prompt) | Low |
| PG-R02 | Task without a major version (`Task` instead of `Task@2`) or a deprecated task version | Medium |
| PG-R03 | Deployment with no rollback path or health check after the deploy step, including stop, deploy, start sequences that cause downtime | Medium |
| PG-R04 | `trigger` or `pr` missing or implicit, so every branch builds, or `batch` missing on a busy branch | Low |
| PG-R05 | Conditions that silently skip stages (`condition: succeeded()` missing after a custom condition, wrong `dependsOn`) | Medium |
| PG-R06 | Hard-coded values duplicated across stages that should be parameters or a template | Low |
| PG-R07 | Irreversible external side effect (resource created in a third-party system, release published, record registered) followed by a step that can fail, with nothing that makes a re-run safe or lets the result be recovered | Medium |
| PG-R08 | `git add .` or `git add -A` in a pipeline that commits, which stages the whole workspace instead of the files the pipeline produced | Low |
| PG-R09 | Pipeline that cannot run: YAML that does not parse (for example an unquoted `*` in a trigger), or a Microsoft-hosted image that has been retired (for example `ubuntu-16.04`, `macOS-10.13`, `vs2017-win2016`). If unsure whether an image is retired, say so and ask the user to check the current list | Medium |

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
- If something depends on settings outside the YAML (environment approvals, branch policies, fork PR settings, service connection scope, variable group contents), do not assume. List it under "To check in Azure DevOps" with the exact place to look.
- If the pipeline is clean on a category, say so in one line rather than inventing low-value findings.

Known false positives, do not report these:

- **Placeholders are not secrets.** A value that is obviously a sample (`dapi0000...`, `<your-token>`, `changeme`, `xxxx`) is not PG-S01. Report it as Low if the design invites users to paste a real secret into the YAML.
- **Public identifiers are not secrets.** Client IDs, tenant IDs, subscription IDs, resource names, SonarCloud project keys and state file names such as `prod.tfstate` are not PG-S01, even when the key contains the word "key" or "id".
- **Secret variables passed to a task input designed for them** are fine: `acrPassword: '$(x)'`, `overrideParameters` feeding an ARM secure parameter, a service connection name.
- **A deployment gated only by its environment** is not PG-S05; it goes under "To check in Azure DevOps".

## 4. Report format

Write the report in the user's language.

1. **Summary**: one sentence verdict, then the count of findings per severity.
2. **Findings**, most severe first. For each:
   - `[Severity] PG-XXX: short title` and `file:line`
   - The offending lines, quoted
   - Why it matters, in one or two sentences, with the concrete attack or failure
   - The fix, as corrected YAML ready to paste
3. **Housekeeping**: PG-R01, PG-R04, PG-R06 and all PG-C rules fire on most pipelines. Do not give them a full finding each. List them here as one line per rule with the lines concerned, and do not count them in the summary.
4. **To check in Azure DevOps**: settings that cannot be seen from the YAML.
5. **Not audited**: external templates and anything that could not be read.

Keep it short. A reader should be able to fix the top three findings in ten minutes.

## 5. Applying fixes

Only edit pipeline files when the user asks. When they do:

- Fix one finding per change so each can be reviewed and reverted on its own.
- Never invent secret values, service connection names or environment names; use a clearly marked placeholder and say what must be filled in.
- When a plain-text secret is found, the fix is not only removing it: tell the user the secret must be rotated, because it remains in the Git history.
