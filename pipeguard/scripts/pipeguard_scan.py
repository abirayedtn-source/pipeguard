#!/usr/bin/env python3
"""PipeGuard scanner: deterministic checks for Azure DevOps YAML pipelines.

Usage:
    pipeguard_scan.py [paths...] [--format text|json|sarif] [--fail-on LEVEL]
                      [--hosting github|azure-repos|unknown] [--root DIR]

Paths may be files or directories. With no path, the current directory is
searched. Local templates referenced by a pipeline are followed and analysed
in the context of the pipeline that includes them.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings at or above
--fail-on, 2 = usage error.

Requires Python 3.8+ and PyYAML.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("pipeguard: PyYAML is required (pip install pyyaml)\n")
    sys.exit(2)

VERSION = "0.2.0"
SEVERITIES = ["low", "medium", "high", "critical"]
HOUSEKEEPING = {"PG-R01", "PG-R04", "PG-C01"}

RULES = {
    "PG-S01": "Secret in plain text",
    "PG-S02": "Script injection through a user-controlled value",
    "PG-S03": "Secret passed on a command line",
    "PG-S04": "Repository token exposed more than needed",
    "PG-S05": "Deployment or publication with no gate",
    "PG-S06": "Unpinned external code",
    "PG-S07": "Self-hosted agent pool",
    "PG-S08": "Free-text parameter selects a sensitive target",
    "PG-S10": "Security step that cannot fail the build",
    "PG-S13": "Pipeline pushes commits to the repository",
    "PG-S14": "Deploy or publish step also runs on pull request builds",
    "PG-S15": "Production stage reachable from any branch",
    "PG-S16": "Key Vault loaded in full",
    "PG-R01": "No timeout",
    "PG-R02": "Task without a version",
    "PG-R04": "No explicit trigger",
    "PG-R08": "git add of the whole workspace",
    "PG-R09": "Pipeline cannot run",
    "PG-C01": "No dependency cache",
}

# Rules that need judgment and are left to the reviewer.
NOT_COVERED = ["PG-S09", "PG-S11", "PG-S12", "PG-R03", "PG-R05", "PG-R06",
               "PG-R07", "PG-C02", "PG-C03", "PG-C04"]

RETIRED_IMAGES = {
    "ubuntu-16.04", "ubuntu 16.04", "ubuntu-18.04", "ubuntu 18.04",
    "macos-10.13", "macos-10.14", "macos-10.15", "macos-11",
    "vs2015-win2012r2", "vs2017-win2016", "win1803", "windows-2016",
}

# ---------------------------------------------------------------- YAML model


class LStr(str):
    """A scalar that remembers where it came from."""
    line = 0
    end_line = 0
    tag = ""


class LMap(dict):
    line = 0
    end_line = 0

    def key_line(self, key):
        return self._key_lines.get(key, self.line)


class LList(list):
    line = 0
    end_line = 0


def _build(node, seen):
    if id(node) in seen:
        return seen[id(node)]
    if isinstance(node, yaml.MappingNode):
        out = LMap()
        out._key_lines = {}
        seen[id(node)] = out
        for k, v in node.value:
            key = str(k.value) if isinstance(k, yaml.ScalarNode) else str(k.start_mark.line)
            out[key] = _build(v, seen)
            out._key_lines[key] = k.start_mark.line + 1
    elif isinstance(node, yaml.SequenceNode):
        out = LList()
        seen[id(node)] = out
        for v in node.value:
            out.append(_build(v, seen))
    else:
        out = LStr(node.value)
        out.tag = node.tag
        seen[id(node)] = out
    out.line = node.start_mark.line + 1
    out.end_line = max(out.line, node.end_mark.line + (0 if node.end_mark.column == 0 else 1))
    return out


class Doc:
    def __init__(self, path, display):
        self.path = path
        self.display = display
        with open(path, encoding="utf-8", errors="replace") as fh:
            self.text = fh.read()
        self.lines = self.text.splitlines()
        self.error = None
        self.root = None
        try:
            node = yaml.compose(self.text, Loader=yaml.SafeLoader)
            self.root = _build(node, {}) if node is not None else LMap()
        except yaml.YAMLError as exc:
            mark = getattr(exc, "problem_mark", None)
            self.error = (mark.line + 1 if mark else 1, str(getattr(exc, "problem", exc)))

    def span(self, node):
        """Raw source lines covered by a node: (line number, text)."""
        for no in range(node.line, min(node.end_line, len(self.lines)) + 1):
            text = self.lines[no - 1]
            if text.lstrip().startswith("#"):
                continue
            yield no, text


def is_expr_key(key):
    return key.strip().startswith("${{")


def items_of(seq, conds=()):
    """Flatten a YAML list, descending through ${{ if }} / ${{ each }} wrappers."""
    if not isinstance(seq, list):
        return
    for item in seq:
        if isinstance(item, LMap) and len(item) == 1 and is_expr_key(next(iter(item))):
            key = next(iter(item))
            inner = item[key]
            if isinstance(inner, list):
                yield from items_of(inner, conds + (key,))
            elif isinstance(inner, LMap):
                yield inner, conds + (key,)
        elif isinstance(item, LMap):
            yield item, conds


def truthy(value):
    return isinstance(value, str) and value.strip().lower() == "true"


def falsy(value):
    return isinstance(value, str) and value.strip().lower() == "false"


# ------------------------------------------------------------ pipeline model

SCRIPT_KEYS = ("script", "bash", "pwsh", "powershell")
INLINE_INPUTS = ("script", "inlineScript", "Inline", "inline", "InlineScript")
ARG_INPUTS = ("arguments", "commandOptions", "customCommand", "ScriptArguments", "scriptArguments")


class Step:
    def __init__(self, doc, node, conds, job, from_template):
        self.doc = doc
        self.node = node
        self.conds = conds
        self.job = job
        self.from_template = from_template
        self.line = node.line
        self.task = ""
        self.task_name = ""
        self.inputs = LMap()
        self.scripts = []   # inline script bodies
        self.args = []      # argument strings handed to a script or tool
        if "task" in node and isinstance(node["task"], str):
            self.task = str(node["task"])
            self.task_name = self.task.split("@")[0]
            if isinstance(node.get("inputs"), LMap):
                self.inputs = node["inputs"]
        for key in SCRIPT_KEYS:
            if isinstance(node.get(key), LStr):
                self.scripts.append(node[key])
        for key in INLINE_INPUTS:
            if isinstance(self.inputs.get(key), LStr):
                self.scripts.append(self.inputs[key])
        for key in ARG_INPUTS:
            if isinstance(self.inputs.get(key), LStr):
                self.args.append(self.inputs[key])

    @property
    def condition(self):
        return " ".join([str(self.node.get("condition", ""))] + list(self.conds))

    def text(self):
        parts = [self.task, str(self.node.get("displayName", ""))]
        parts += [str(s) for s in self.scripts]
        return "\n".join(parts)


class Job:
    def __init__(self, doc, node, conds, stage, kind):
        self.doc = doc
        self.node = node
        self.conds = conds
        self.stage = stage
        self.kind = kind            # "job", "deployment" or "implicit"
        self.name = str(node.get("deployment") or node.get("job") or "")
        self.steps = []

    @property
    def environment(self):
        env = self.node.get("environment")
        if isinstance(env, LMap):
            env = env.get("name", "")
        return str(env or "")

    @property
    def condition(self):
        return " ".join([str(self.node.get("condition", ""))] + list(self.conds))


class Stage:
    def __init__(self, doc, node, conds, implicit=False):
        self.doc = doc
        self.node = node
        self.conds = conds
        self.implicit = implicit
        self.name = "" if implicit else str(node.get("stage") or "")
        self.jobs = []

    @property
    def condition(self):
        if self.implicit:
            return ""
        return " ".join([str(self.node.get("condition", ""))] + list(self.conds))


class Pipeline:
    """A root pipeline file with its local templates resolved."""

    def __init__(self, doc, loader):
        self.doc = doc
        self.loader = loader
        self.stages = []
        self.docs = [doc]
        self.external_templates = []   # (doc, line, ref)
        self.missing_templates = []
        root = doc.root if isinstance(doc.root, LMap) else LMap()
        self.root = root
        self._load_root(root)

    # template resolution -------------------------------------------------
    def _template(self, from_doc, ref, line):
        ref = str(ref).strip()
        if "@" in ref and not ref.endswith("@self"):
            self.external_templates.append((from_doc, line, ref))
            return None
        ref = ref.split("@")[0]
        if "${{" in ref or "$(" in ref:
            return None
        target = self.loader.resolve(from_doc, ref)
        if target is None:
            self.missing_templates.append((from_doc, line, ref))
            return None
        if target not in self.docs:
            self.docs.append(target)
        return target

    # walking --------------------------------------------------------------
    def _load_root(self, root):
        if isinstance(root.get("extends"), LMap):
            ext = root["extends"]
            if "template" in ext:
                self._template(self.doc, ext["template"], ext.line)
            params = ext.get("parameters")
            if isinstance(params, LMap):
                root = params
        if isinstance(root.get("stages"), list):
            self._stages(self.doc, root["stages"], (), 0)
        elif isinstance(root.get("jobs"), list):
            stage = Stage(self.doc, root, (), implicit=True)
            self.stages.append(stage)
            self._jobs(self.doc, root["jobs"], (), stage, 0)
        elif isinstance(root.get("steps"), list):
            stage = Stage(self.doc, root, (), implicit=True)
            self.stages.append(stage)
            job = Job(self.doc, root, (), stage, "implicit")
            stage.jobs.append(job)
            self._steps(self.doc, root["steps"], (), job, False, 0)

    def _stages(self, doc, seq, conds, depth):
        for node, c in items_of(seq, conds):
            if "template" in node and "stage" not in node:
                target = self._template(doc, node["template"], node.line)
                if target and depth < 8 and isinstance(target.root, LMap):
                    if isinstance(target.root.get("stages"), list):
                        self._stages(target, target.root["stages"], c, depth + 1)
                continue
            stage = Stage(doc, node, c)
            self.stages.append(stage)
            if isinstance(node.get("jobs"), list):
                self._jobs(doc, node["jobs"], c, stage, depth)

    def _jobs(self, doc, seq, conds, stage, depth):
        for node, c in items_of(seq, conds):
            if "template" in node and "job" not in node and "deployment" not in node:
                target = self._template(doc, node["template"], node.line)
                if target and depth < 8 and isinstance(target.root, LMap):
                    if isinstance(target.root.get("jobs"), list):
                        self._jobs(target, target.root["jobs"], c, stage, depth + 1)
                continue
            kind = "deployment" if "deployment" in node else "job"
            job = Job(doc, node, c, stage, kind)
            stage.jobs.append(job)
            if kind == "deployment":
                strategy = node.get("strategy")
                if isinstance(strategy, LMap):
                    for mode in strategy.values():
                        self._hooks(doc, mode, c, job, depth)
            elif isinstance(node.get("steps"), list):
                self._steps(doc, node["steps"], c, job, doc is not self.doc, depth)

    def _hooks(self, doc, mode, conds, job, depth):
        if not isinstance(mode, LMap):
            return
        for hook in mode.values():
            if isinstance(hook, LMap):
                if isinstance(hook.get("steps"), list):
                    self._steps(doc, hook["steps"], conds, job, doc is not self.doc, depth)
                else:
                    self._hooks(doc, hook, conds, job, depth)

    def _steps(self, doc, seq, conds, job, from_template, depth):
        for node, c in items_of(seq, conds):
            if "template" in node and "task" not in node:
                target = self._template(doc, node["template"], node.line)
                if target and depth < 8 and isinstance(target.root, LMap):
                    if isinstance(target.root.get("steps"), list):
                        self._steps(target, target.root["steps"], c, job, True, depth + 1)
                continue
            job.steps.append(Step(doc, node, c, job, from_template))

    def jobs(self):
        for stage in self.stages:
            yield from stage.jobs

    def steps(self):
        for job in self.jobs():
            yield from job.steps


class Loader:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.cache = {}

    def display(self, path):
        try:
            rel = os.path.relpath(path, self.root)
        except ValueError:
            rel = path
        return path.replace(os.sep, "/") if rel.startswith("..") else rel.replace(os.sep, "/")

    def load(self, path):
        path = os.path.abspath(path)
        if path not in self.cache:
            self.cache[path] = Doc(path, self.display(path))
        return self.cache[path]

    def resolve(self, from_doc, ref):
        candidates = []
        if ref.startswith("/"):
            candidates.append(os.path.join(self.root, ref.lstrip("/")))
        else:
            candidates.append(os.path.join(os.path.dirname(from_doc.path), ref))
            candidates.append(os.path.join(self.root, ref))
        for cand in candidates:
            if os.path.isfile(cand):
                return self.load(cand)
        return None


# ------------------------------------------------------------------ helpers

SECRET_WORD = re.compile(
    r"(password|passwd|pwd|secret|token|apikey|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"connection[_-]?string|credential)", re.I)
SECRET_TAIL = re.compile(r"(key|pat|sas)$", re.I)
NOT_SECRET_NAME = re.compile(
    r"(name|url|uri|id|path|file|filter|certificate|vault|endpoint|enabled|type|version|"
    r"timeout|expiry|expiration|length|scope|audience)$", re.I)
NOT_SECRET_KEYWORD = re.compile(
    r"(keyvault|projectkey|cachekey|rmkey|statekey|partitionkey|primarykey(name)?$|publickey|"
    r"tokenurl|tokenendpoint|secretsfilter|secretname|accesstokenscope|feedcredentials|"
    r"credentialsoption|credentialtype|credentialprovider|serviceconnection|dockerregistry)", re.I)
PLACEHOLDER = re.compile(
    r"(^<.*>$|^\*+$|^x{3,}$|0{8,}|changeme|change[_-]me|your[_-]|example|dummy|placeholder|"
    r"redacted|todo|replace[_-]?me|sample|^\.{3}$)", re.I)
VALUE_PATTERNS = [
    (re.compile(r"AccountKey=[A-Za-z0-9+/=]{20,}"), "storage account key"),
    (re.compile(r"SharedAccessSignature=[^;\s'\"]{10,}"), "shared access signature"),
    (re.compile(r"[?&]sig=[A-Za-z0-9%+/=]{20,}"), "SAS URL signature"),
    (re.compile(r"\bghp_[A-Za-z0-9]{30,}"), "GitHub token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}"), "GitHub token"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\."), "JSON web token"),
    (re.compile(r"(?i)\bpassword\s*=\s*[^\s;$'\"<{]{6,}\s*;"), "password in a connection string"),
]
MACRO = re.compile(r"\$\(([A-Za-z_][\w.-]*)\)")
PARAM = re.compile(r"\$\{\{\s*parameters\.([\w]+)\s*\}\}")
PARAM_INDEX = re.compile(r"\$\{\{\s*parameters\[['\"]([\w]+)['\"]\]\s*\}\}")
USER_VARS = re.compile(
    r"\$\((Build\.SourceBranchName|Build\.SourceBranch|Build\.SourceVersionMessage|"
    r"Build\.RequestedFor|Build\.RequestedForEmail|Build\.QueuedBy|"
    r"System\.PullRequest\.SourceBranch|System\.PullRequest\.TargetBranch)\)", re.I)
SECURITY_STEP = re.compile(
    r"(sonar|snyk|trivy|wiz@|checkmarx|whitesource|\bmend\b|credscan|dependency.?check|owasp|"
    r"npm audit|yarn audit|pnpm audit|pip-audit|safety check|bandit|semgrep|codeql|gitleaks|"
    r"tfsec|checkov|terrascan|grype|anchore|vulnerab|security|secret.?scan|codesign|"
    r"esrpcodesigning|\bsign(tool|client)?\b)", re.I)
NOT_SECURITY_STEP = re.compile(r"(publishtestresults|publishcodecoverageresults|publishbuildartifacts)", re.I)

DEPLOY_TASKS = {
    "azurewebapp", "azurermwebappdeployment", "azurefunctionapp", "azurefunctionappcontainer",
    "azurewebappcontainer", "kubernetesmanifest", "helmdeploy", "azurecontainerapps",
    "azureresourcemanagertemplatedeployment", "azureresourcegroupdeployment", "azurefilecopy",
    "azurestaticwebapp", "sqlazuredacpacdeployment", "azurespringcloud", "azuremysqldeployment",
    "iiswebappdeploymentonmachinegroup", "servicefabricdeploy", "githubrelease",
    "octopusdeployrelease", "octopuscreaterelease", "twineauthenticate",
}
DEPLOY_COMMANDS = re.compile(
    r"(\bterraform\s+(apply|destroy)\b|\bkubectl\s+(apply|set image|rollout restart)\b|"
    r"\bhelm\s+(upgrade|install)\b|\baz\s+(webapp|functionapp)\s+(deploy|deployment|restart|up|config)\b|"
    r"\baz\s+deployment\s+\w+\s+create\b|\baz\s+containerapp\s+(update|up|create)\b|"
    r"\baz\s+storage\s+blob\s+(upload|upload-batch|sync)\b|\bnpm\s+publish\b|\byarn\s+publish\b|"
    r"\bdotnet\s+nuget\s+push\b|\bnuget(\.exe)?\s+push\b|\btwine\s+upload\b|\bcargo\s+publish\b|"
    r"\bgem\s+push\b|\bPublish-Module\b|\bvsce\s+publish\b|"
    r"\b(?:npm|yarn|pnpm)\s+run\s+(?:deploy|release|publish)[\w:-]*|\bnpx\s+run-[sp]\s+(?:deploy|release|publish)[\w:-]*|"
    r"(?:^|[\s/\\'\"])(?:deploy|release|publish)[\w.-]*\.(?:sh|ps1|py)\b)", re.I)
BRANCH_OR_PR = re.compile(r"(Build\.SourceBranch|Build\.Reason|PullRequest)", re.I)
PROD = re.compile(r"(^|[^a-z])(prod|production|prd)([^a-z]|$)", re.I)


def secretish(name):
    if NOT_SECRET_KEYWORD.search(name) or NOT_SECRET_NAME.search(name):
        return False
    return bool(SECRET_WORD.search(name) or SECRET_TAIL.search(name))


def is_literal(value):
    v = str(value).strip()
    if not v or v.lower() in ("true", "false", "null", "none", "''", '""'):
        return False
    return not ("$(" in v or "${{" in v or "$[" in v or v.startswith("$env:") or re.match(r"^\$\w+$", v))


class Report:
    def __init__(self):
        self.findings = []
        self.checks = []
        self._seen = set()

    def add(self, rule, severity, doc, line, message, fix=""):
        key = (rule, doc.display, line)
        if key in self._seen:
            return
        self._seen.add(key)
        quote = doc.lines[line - 1].strip() if 0 < line <= len(doc.lines) else ""
        self.findings.append({
            "rule": rule, "title": RULES[rule], "severity": severity,
            "file": doc.display, "line": line, "quote": quote[:200],
            "message": message, "fix": fix,
            "housekeeping": rule in HOUSEKEEPING,
        })

    def check(self, topic, doc, line, message):
        key = ("check", topic, doc.display, message)
        if key in self._seen:
            return
        self._seen.add(key)
        self.checks.append({"topic": topic, "file": doc.display, "line": line, "message": message})


# -------------------------------------------------------------------- rules


def walk(node):
    """Every mapping in a document, depth first."""
    if isinstance(node, LMap):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


def rule_secrets(pipe, rep):
    for doc in pipe.docs:
        if doc.root is None:
            continue
        for no, text in enumerate(doc.lines, 1):
            if text.lstrip().startswith("#"):
                continue
            for pattern, label in VALUE_PATTERNS:
                if pattern.search(text):
                    rep.add("PG-S01", "critical", doc, no,
                            f"This line contains what looks like a {label}.",
                            "Move it to a Key Vault linked variable group, then rotate it: it stays in the Git history.")
        for m in walk(doc.root):
            pairs = []
            if "name" in m and "value" in m and isinstance(m["name"], str):
                pairs.append((str(m["name"]), m["value"], m.key_line("value")))
            for key, value in m.items():
                if isinstance(value, LStr):
                    pairs.append((key, value, m.key_line(key)))
            for name, value, line in pairs:
                if not isinstance(value, LStr) or not secretish(name) or not is_literal(value):
                    continue
                v = str(value).strip()
                if len(v) < 6 or " " in v.strip() and len(v.split()) > 3:
                    continue
                if PLACEHOLDER.search(v):
                    rep.add("PG-S01", "low", doc, line,
                            f"`{name}` holds a placeholder. The layout invites pasting a real secret into the YAML.",
                            "Read the value from a secret variable or a Key Vault linked variable group.")
                else:
                    rep.add("PG-S01", "critical", doc, line,
                            f"`{name}` is set to a literal value in the YAML.",
                            "Move it to a Key Vault linked variable group, then rotate it: it stays in the Git history.")


def free_text_parameters(root):
    names = set()
    params = root.get("parameters")
    if isinstance(params, list):
        for p in params:
            if isinstance(p, LMap) and "name" in p:
                ptype = str(p.get("type", "string")).lower()
                if ptype == "string" and "values" not in p:
                    names.add(str(p["name"]))
    return names


def rule_injection(pipe, rep):
    free = free_text_parameters(pipe.root)
    for step in pipe.steps():
        for script in step.scripts:
            for no, text in step.doc.span(script):
                if not step.from_template:
                    for match in list(PARAM.finditer(text)) + list(PARAM_INDEX.finditer(text)):
                        if match.group(1) in free:
                            rep.add("PG-S02", "high", step.doc, no,
                                    f"Free-text parameter `{match.group(1)}` is pasted into the script before it runs, so its value can inject commands.",
                                    "Add a `values:` allow-list or validate it, and read it through `env:` instead.")
                match = USER_VARS.search(text)
                if match:
                    rep.add("PG-S02", "medium", step.doc, no,
                            f"`$({match.group(1)})` is controlled by whoever names the branch, tag or commit, and is pasted into the script.",
                            f"Read the matching environment variable instead (for example `$BUILD_SOURCEBRANCH`).")


def rule_secret_on_cli(pipe, rep):
    for step in pipe.steps():
        targets = [(s, True) for s in step.scripts] + [(a, False) for a in step.args]
        for node, inline in targets:
            for no, text in step.doc.span(node):
                for match in MACRO.finditer(text):
                    name = match.group(1)
                    if name.lower() == "system.accesstoken":
                        rep.add("PG-S04", "high", step.doc, no,
                                "`$(System.AccessToken)` is written into the script text.",
                                "Map it in `env:` on this step and read the environment variable.")
                    elif secretish(name.split(".")[-1]):
                        rep.add("PG-S03", "high" if inline else "medium", step.doc, no,
                                f"Secret `$({name})` is expanded into a command line, where it lands in the script file and the process arguments.",
                                "Map it in `env:` on this step and read the environment variable.")
                if inline and re.search(r"(^|\s)set\s+-[a-wyz]*x|Set-PSDebug\s+-Trace", text):
                    if any(k in step.node for k in ("env",)):
                        rep.add("PG-S03", "medium", step.doc, no,
                                "Command tracing is on in a step that receives secrets through `env:`.",
                                "Remove the tracing or limit it to the commands that need it.")
    for doc in pipe.docs:
        if doc.root is None:
            continue
        for m in walk(doc.root):
            for key in ("system.debug", "System.Debug"):
                if truthy(m.get(key)) or (str(m.get("name", "")).lower() == "system.debug" and truthy(m.get("value"))):
                    rep.add("PG-S03", "medium", doc, m.key_line(key) if key in m else m.line,
                            "`system.debug` is committed as true: every run logs in verbose mode.",
                            "Remove it and set it at queue time when needed.")


def rule_access_token(pipe, rep):
    for job in pipe.jobs():
        runs_code_after = False
        checkout_step = None
        for step in job.steps:
            if "checkout" in step.node and truthy(step.node.get("persistCredentials")):
                checkout_step = step
            elif checkout_step and (step.scripts or step.task):
                runs_code_after = True
        if checkout_step:
            line = checkout_step.node.key_line("persistCredentials")
            pushes = any(re.search(r"\bgit\s+push\b", str(s)) for st in job.steps for s in st.scripts)
            sev = "high" if runs_code_after else "medium"
            msg = "`persistCredentials: true` leaves the repository token in the Git configuration for every later step in this job."
            if not pushes:
                msg += " No step in this job pushes, so it is not needed."
            rep.add("PG-S04", sev, checkout_step.doc, line, msg,
                    "Remove it, or pass the token only to the step that pushes through `env:`.")
        for scope in (job.node,):
            for block in (scope.get("variables"), scope.get("env")):
                if isinstance(block, LMap):
                    for key, value in block.items():
                        if isinstance(value, str) and "System.AccessToken" in value and job.kind != "implicit":
                            rep.add("PG-S04", "medium", job.doc, block.key_line(key),
                                    "`System.AccessToken` is mapped for the whole job.",
                                    "Map it in `env:` on the single step that needs it.")


def deploy_evidence(step):
    """Return (line, description) if the step deploys or publishes, else None."""
    name = step.task_name.lower()
    if name in DEPLOY_TASKS:
        return step.node.key_line("task"), f"task `{step.task}`"
    command = str(step.inputs.get("command", "")).lower()
    if name == "npm" and command == "publish":
        return step.node.key_line("task"), "`npm publish`"
    if name in ("nugetcommand", "dotnetcorecli") and command == "push":
        if str(step.inputs.get("nuGetFeedType", "internal")).strip().strip("'\"").lower() == "external":
            return step.node.key_line("task"), "a NuGet push to an external feed"
    if name.startswith("terraformtask") or name == "terraformcli":
        if command in ("apply", "destroy"):
            return step.node.key_line("task"), f"`terraform {command}`"
    for script in step.scripts:
        for no, text in step.doc.span(script):
            match = DEPLOY_COMMANDS.search(text)
            if match:
                return no, f"`{match.group(1).strip()}`"
    return None


def deploy_is_guess(step):
    """True when the only evidence is the name of a script (deploy.sh, npm run release)."""
    if step.task_name.lower() in DEPLOY_TASKS or str(step.inputs.get("command", "")).lower() in ("publish", "push", "apply", "destroy"):
        return False
    for script in step.scripts:
        for _, text in step.doc.span(script):
            match = DEPLOY_COMMANDS.search(text)
            if match:
                return bool(re.search(r"\.(sh|ps1|py)$|\brun(-[sp])?\s", match.group(1).strip(), re.I))
    return False


def rule_gates(pipe, rep, hosting):
    pr_trigger = pipe.root.get("pr")
    pr_off = isinstance(pr_trigger, str) and pr_trigger.strip().lower() == "none"
    manual_gate = False
    for step in pipe.steps():
        if step.task_name.lower() == "manualvalidation":
            manual_gate = True
            if str(step.inputs.get("onTimeout", "reject")).strip().strip("'\"").lower() == "resume":
                rep.add("PG-S05", "medium", step.doc, step.inputs.key_line("onTimeout"),
                        "The manual validation resumes on timeout: with no answer, the deployment approves itself.",
                        "Set `onTimeout: 'reject'`.")
    for job in pipe.jobs():
        for step in job.steps:
            evidence = deploy_evidence(step)
            if not evidence:
                continue
            line, what = evidence
            if job.kind != "deployment" and not manual_gate:
                guess = deploy_is_guess(step)
                rep.add("PG-S05", "medium" if guess else "high", step.doc, line,
                        (f"{what} looks like a deployment and runs in an ordinary job, so no approval or check can apply to it."
                         if guess else f"{what} runs in an ordinary job, so no approval or check can apply to it."),
                        "Move it into a `deployment` job bound to an `environment` and configure approvals on that environment.")
            guarded = BRANCH_OR_PR.search(" ".join([step.condition, job.condition, job.stage.condition]))
            if not pr_off and not guarded:
                if hosting == "github":
                    rep.add("PG-S14", "high", step.doc, line,
                            f"{what} has no condition excluding pull requests, and PR builds are on for this repository.",
                            "Add `pr: none`, or a condition such as `ne(variables['Build.Reason'], 'PullRequest')`.")
                elif hosting == "unknown":
                    rep.check("Pull request builds", step.doc, line,
                              f"{what} has no condition excluding pull requests. If the repository is on GitHub or Bitbucket, or a build validation policy runs this pipeline, a pull request would reach it.")
        if job.kind == "deployment" and job.environment:
            rep.check("Environment approvals", job.doc, job.node.key_line("environment"),
                      f"Confirm approvals or checks are configured on environment `{job.environment}`.")


def rule_prod_branches(pipe, rep):
    for stage in pipe.stages:
        for job in stage.jobs:
            label = " ".join([stage.name, job.name, job.environment])
            if not PROD.search(label):
                continue
            if not any(deploy_evidence(s) for s in job.steps) and job.kind != "deployment":
                continue
            if BRANCH_OR_PR.search(" ".join([stage.condition, job.condition])):
                cond = " ".join([stage.condition, job.condition])
                if re.search(r"Build\.Reason'\]\s*,\s*'Manual'", cond) and re.search(r"\bor\s*\(", cond):
                    rep.add("PG-S15", "medium", job.doc, job.node.line,
                            "The production stage accepts any manual run, whatever the branch.",
                            "Require the branch as well, for example `eq(variables['Build.SourceBranch'], 'refs/heads/main')`.")
                continue
            line = stage.node.line if not stage.implicit else job.node.line
            doc = stage.doc if not stage.implicit else job.doc
            rep.add("PG-S15", "medium", doc, line,
                    "Nothing in the YAML limits this production stage to the main branch: a run from any branch reaches it.",
                    "Add a branch condition on the stage, and a branch control check on the environment.")


SHELL_PIPE = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*\|\s*(iex|Invoke-Expression)\b", re.I)
SHELL_SUBST = re.compile(r"\b(ba|z)?sh\s+<\(\s*(curl|wget)\b", re.I)
DOWNLOAD = re.compile(r"\b(curl\b[^\n]*\s-[A-Za-z]*[Oo]\b|wget\b|Invoke-WebRequest\b[^\n]*-OutFile|iwr\b[^\n]*-OutFile)", re.I)
EXECUTE = re.compile(r"(chmod\s+\+x|\bsudo\s+\./|^\s*\./\S+\.(sh|py)|\bbash\s+\S+\.sh\b|^\s*&\s*\$|\bsh\s+\S+\.sh\b)", re.I | re.M)
GIT_CLONE = re.compile(r"\bgit\s+clone\s+(?!.*(--branch|-b)\s+v?\d)['\"]?https?://", re.I)
UNPINNED = [
    (re.compile(r"\bnpm\s+(install|i)\s+(?:-g|--global)\s+((?:@[\w-]+/)?[\w.-]+)(?=\s|$)(?!@)"), "npm package `{0}` installed globally with no version"),
    (re.compile(r"\bdotnet\s+tool\s+install\b(?![^\n]*--version)[^\n]*"), "`dotnet tool install` with no `--version`"),
    (re.compile(r"\bInstall-Module\b(?![^\n]*(-RequiredVersion|-Repository))[^\n]*", re.I), "`Install-Module` with no `-RequiredVersion`"),
    (re.compile(r"\bpip3?\s+install\s+(?!.*(-r\s|--requirement|==|\s-e\s|\s\.\s*$|--upgrade\s+pip\s*$))[^\n]*"), "`pip install` with no pinned version"),
    (re.compile(r"@latest\b"), "`@latest`"),
]


def job_is_sensitive(job):
    if job.kind == "deployment":
        return True
    if any(deploy_evidence(s) for s in job.steps):
        return True
    for step in job.steps:
        if step.inputs.get("azureSubscription") or step.inputs.get("connectedServiceNameARM"):
            return True
    return False


def rule_unpinned(pipe, rep):
    pipeline_sensitive = any(job_is_sensitive(j) for j in pipe.jobs())
    for job in pipe.jobs():
        sensitive = job_is_sensitive(job)
        for step in job.steps:
            for script in step.scripts:
                body = "\n".join(text for _, text in step.doc.span(script))
                downloads = [(no, text) for no, text in step.doc.span(script) if DOWNLOAD.search(text)]
                for no, text in step.doc.span(script):
                    if SHELL_PIPE.search(text) or SHELL_SUBST.search(text):
                        rep.add("PG-S06", "high", step.doc, no,
                                "A script is downloaded and executed in one go: whoever controls that URL controls this job.",
                                "Install a pinned version from a package manager, or download a fixed version and verify its checksum.")
                    elif GIT_CLONE.search(text):
                        rep.add("PG-S06", "high" if pipeline_sensitive else "medium", step.doc, no,
                                "Another repository is cloned at its default branch and used by this pipeline.",
                                "Clone a tag or a commit, or declare it under `resources.repositories` with a pinned `ref`.")
                    else:
                        for pattern, label in UNPINNED:
                            match = pattern.search(text)
                            if match:
                                what = label.format(*match.groups()) if match.groups() else label
                                rep.add("PG-S06", "medium" if sensitive else "low", step.doc, no,
                                        f"Unpinned tool: {what}.", "Pin an exact version.")
                                break
                if downloads and EXECUTE.search(body):
                    no, text = downloads[0]
                    if not (SHELL_PIPE.search(text) or SHELL_SUBST.search(text)):
                        branch_url = re.search(r"/(master|main|HEAD)/", text)
                        rep.add("PG-S06", "high" if (sensitive or branch_url) else "medium", step.doc, no,
                                "A file is downloaded and then executed, with no checksum verification.",
                                "Download a fixed version and verify its checksum before running it.")
            if step.task_name.lower() == "dotnetcorecli" and str(step.inputs.get("custom", "")).strip().lower() == "tool":
                arguments = str(step.inputs.get("arguments", ""))
                if re.search(r"(^|\s)install\b", arguments) and "--version" not in arguments:
                    prerelease = "--prerelease" in arguments
                    rep.add("PG-S06", "high" if (sensitive and prerelease) else ("medium" if sensitive else "low"),
                            step.doc, step.inputs.key_line("arguments"),
                            "Unpinned tool: `dotnet tool install` with no `--version`" + (", taking prereleases." if prerelease else "."),
                            "Pin an exact version with `--version`.")
            # installer tasks on a floating version
            for key in ("terraformVersion", "version", "versionSpec", "helmVersionToInstall", "kubectlVersion"):
                value = str(step.inputs.get(key, "")).strip().strip("'\"").lower()
                if value in ("latest", "*") and step.task_name.lower() not in ("usenode", "nodetool", "usedotnet", "usepythonversion"):
                    rep.add("PG-S06", "medium" if sensitive else "low", step.doc, step.inputs.key_line(key),
                            f"`{step.task}` installs a floating version (`{value}`).", "Pin an exact version.")
        container = job.node.get("container")
        if isinstance(container, LMap):
            container = container.get("image")
        if isinstance(container, LStr) and "$(" not in container and "${{" not in container:
            image = str(container).strip()
            if image.endswith(":latest") or (":" not in image.split("/")[-1] and "@" not in image and "/" in image):
                rep.add("PG-S06", "medium", job.doc, container.line,
                        f"Job container `{image}` is not pinned to a version.", "Pin a version tag or a digest.")
    resources = pipe.root.get("resources")
    if isinstance(resources, LMap):
        for repo, _ in items_of(resources.get("repositories") or []):
            name = str(repo.get("repository", ""))
            if name and name != "self" and "ref" not in repo:
                rep.add("PG-S06", "high", pipe.doc, repo.line,
                        f"Repository resource `{name}` has no `ref`: its templates come from whatever is on the default branch.",
                        "Pin `ref` to a tag or a commit.")
        for cont, _ in items_of(resources.get("containers") or []):
            image = str(cont.get("image", "")).strip()
            if image and "$(" not in image and (image.endswith(":latest") or ":" not in image.split("/")[-1]) and "@" not in image:
                rep.add("PG-S06", "medium", pipe.doc, cont.key_line("image"),
                        f"Container resource `{image}` is not pinned to a version.", "Pin a version tag or a digest.")


def pool_name(pool):
    if isinstance(pool, LStr):
        name = str(pool).strip()
        return None if name.lower() in ("server", "") or "$(" in name else name
    if isinstance(pool, LMap) and "vmImage" not in pool and "name" in pool:
        name = str(pool["name"]).strip()
        return None if name.lower() in ("azure pipelines", "hosted", "") else name
    return None


def rule_pools(pipe, rep):
    scopes = [(pipe.doc, pipe.root)] + [(j.doc, j.node) for j in pipe.jobs() if j.kind != "implicit"]
    for doc, node in scopes:
        pool = node.get("pool")
        name = pool_name(pool)
        if name:
            rep.check("Self-hosted agents", doc, node.key_line("pool"),
                      f"Pool `{name}` looks self-hosted. If the repository is public or builds pull requests from forks, untrusted code can run on that machine (PG-S07).")
        image = None
        if isinstance(pool, LMap) and isinstance(pool.get("vmImage"), LStr):
            image = pool["vmImage"]
        if image is not None and str(image).strip().lower() in RETIRED_IMAGES:
            rep.add("PG-R09", "medium", doc, image.line,
                    f"Hosted image `{str(image).strip()}` has been retired: this pipeline can no longer run.",
                    "Use a current image such as `ubuntu-latest` or `windows-latest`.")
    # images set through a variable or a matrix
    for doc in pipe.docs:
        if doc.root is None:
            continue
        for m in walk(doc.root):
            for key, value in m.items():
                if isinstance(value, LStr) and key != "vmImage" and re.search(r"image", key, re.I):
                    if str(value).strip().lower() in RETIRED_IMAGES:
                        rep.add("PG-R09", "medium", doc, m.key_line(key),
                                f"Hosted image `{str(value).strip()}` has been retired.",
                                "Use a current image such as `ubuntu-latest` or `windows-latest`.")


SENSITIVE_INPUTS = ("azureSubscription", "connectedServiceName", "connectedServiceNameARM",
                    "kubernetesServiceConnection", "environmentServiceNameAzureRM",
                    "backendServiceArm", "filePath", "scriptPath", "ScriptPath")


def rule_free_text_targets(pipe, rep):
    free = free_text_parameters(pipe.root)
    if not free:
        return

    def uses(value):
        for match in list(PARAM.finditer(str(value))) + list(PARAM_INDEX.finditer(str(value))):
            if match.group(1) in free:
                return match.group(1)
        return None

    for job in pipe.jobs():
        if job.doc is pipe.doc and job.kind == "deployment":
            name = uses(job.node.get("environment", "")) if isinstance(job.node.get("environment"), str) else None
            if name:
                rep.add("PG-S08", "medium", job.doc, job.node.key_line("environment"),
                        f"Free-text parameter `{name}` selects the environment.",
                        "Add a `values:` allow-list to the parameter.")
        for step in job.steps:
            if step.from_template:
                continue
            for key in SENSITIVE_INPUTS:
                name = uses(step.inputs.get(key, ""))
                if name:
                    rep.add("PG-S08", "medium", step.doc, step.inputs.key_line(key),
                            f"Free-text parameter `{name}` selects `{key}`.",
                            "Add a `values:` allow-list to the parameter.")


SCANNER_SWITCHES = {
    "succeedonfailures": True, "continueonvulnerablepackagescanerror": True,
    "failonissues": False, "failonalert": False, "failonseverity": None,
    "breakbuild": False, "failbuildonpolicyfail": False,
}
AUDIT_OR_TRUE = re.compile(
    r"\b(npm audit|yarn audit|pnpm audit|pip-audit|safety check|trivy|snyk|grype|bandit|semgrep|"
    r"gitleaks|tfsec|checkov)\b[^\n|&;]*(\|\|\s*true|;\s*true\s*$|\|\|\s*exit\s+0|--exit-code[= ]0)", re.I)


def rule_security_steps(pipe, rep):
    for doc in pipe.docs:
        if doc.root is None:
            continue
        for m in walk(doc.root):
            for key, value in m.items():
                want = SCANNER_SWITCHES.get(key.lower(), "absent")
                if want == "absent" or want is None:
                    continue
                if (want is True and truthy(value)) or (want is False and falsy(value)):
                    rep.add("PG-S10", "medium", doc, m.key_line(key),
                            f"`{key}: {str(value).strip()}` lets the build pass when the scan finds problems.",
                            "Let the scan fail the build and handle exceptions in the scanner's own configuration.")
    for step in pipe.steps():
        text = step.text()
        if truthy(step.node.get("continueOnError")) and SECURITY_STEP.search(text) and not NOT_SECURITY_STEP.search(step.task):
            rep.add("PG-S10", "medium", step.doc, step.node.key_line("continueOnError"),
                    "`continueOnError: true` on a security or signing step: its failure does not stop the pipeline.",
                    "Remove `continueOnError` from this step.")
        for script in step.scripts:
            for no, line in step.doc.span(script):
                if AUDIT_OR_TRUE.search(line):
                    rep.add("PG-S10", "medium", step.doc, no,
                            "The scan's exit code is discarded, so it can never fail the build.",
                            "Remove the override and let the command fail.")


def rule_git(pipe, rep):
    for step in pipe.steps():
        for script in step.scripts:
            for no, text in step.doc.span(script):
                if re.search(r"\bgit\b[^\n]*\bpush\b", text) and "--dry-run" not in text:
                    rep.add("PG-S13", "medium", step.doc, no,
                            "The pipeline pushes commits itself, which can bypass pull requests and branch policies.",
                            "Push to a separate branch and open a pull request, or confirm the build identity cannot bypass policies.")
                if re.search(r"\bgit\s+add\s+(\.|-A\b|--all\b)", text):
                    rep.add("PG-R08", "low", step.doc, no,
                            "`git add` stages the whole workspace, not only the files this pipeline produced.",
                            "Stage the specific paths the pipeline generated.")


def rule_keyvault(pipe, rep):
    for step in pipe.steps():
        if step.task_name.lower() == "azurekeyvault":
            value = str(step.inputs.get("SecretsFilter", step.inputs.get("secretsFilter", "*"))).strip().strip("'\"")
            if value == "*":
                key = "SecretsFilter" if "SecretsFilter" in step.inputs else ("secretsFilter" if "secretsFilter" in step.inputs else None)
                line = step.inputs.key_line(key) if key else step.node.key_line("task")
                rep.add("PG-S16", "low", step.doc, line,
                        "Every secret in the vault is loaded into this job.",
                        "List only the secrets this job needs in `SecretsFilter`.")


def rule_housekeeping(pipe, rep):
    for step in pipe.steps():
        if step.task and "@" not in step.task and "$" not in step.task:
            rep.add("PG-R02", "medium", step.doc, step.node.key_line("task"),
                    f"Task `{step.task}` has no major version.", "Add the major version, for example `@2`.")
    if "trigger" not in pipe.root and "extends" not in pipe.root and pipe.stages:
        rep.add("PG-R04", "low", pipe.doc, 1,
                "No `trigger` key: every push to every branch starts this pipeline.",
                "Declare the branches explicitly, or `trigger: none`.")
    for job in pipe.jobs():
        if "timeoutInMinutes" in job.node:
            continue
        risky = job.kind == "deployment" or any(deploy_evidence(s) for s in job.steps)
        if risky:
            line = job.node.line if job.kind != "implicit" else (job.steps[0].line if job.steps else 1)
            rep.add("PG-R01", "low", job.doc, line,
                    "This deploying job has no `timeoutInMinutes`.", "Set a timeout on the job.")
    restore = re.compile(r"\b(npm\s+(ci|install)|yarn(\s+install)?\s*$|pnpm\s+install|pip3?\s+install\s+-r|dotnet\s+restore|nuget\s+restore|mvn\s|gradle\w*\s)", re.I | re.M)
    for job in pipe.jobs():
        has_cache = any(s.task_name.lower() in ("cache", "cachebeta") for s in job.steps)
        if has_cache:
            continue
        for step in job.steps:
            hit = None
            for script in step.scripts:
                for no, text in step.doc.span(script):
                    if restore.search(text):
                        hit = no
                        break
                if hit:
                    break
            if hit:
                rep.add("PG-C01", "low", step.doc, hit,
                        "Dependencies are restored with no `Cache@2` step in this job.",
                        "Add a `Cache@2` step keyed on the lock file.")
                break


def rule_context(pipe, rep):
    for doc, line, ref in pipe.external_templates:
        rep.check("Not audited", doc, line, f"External template `{ref}` was not read.")
    for doc, line, ref in pipe.missing_templates:
        rep.check("Not audited", doc, line, f"Template `{ref}` was not found on disk.")
    groups = set()
    for doc in pipe.docs:
        if doc.root is None:
            continue
        for m in walk(doc.root):
            if isinstance(m.get("group"), LStr) and len(m) == 1:
                groups.add((str(m["group"]), doc, m.line))
    for name, doc, line in sorted(groups, key=lambda g: g[0]):
        rep.check("Variable groups", doc, line,
                  f"Confirm variable group `{name}` is linked to a Key Vault and restricted to the pipelines that need it.")


def scan_pipeline(pipe, rep, hosting):
    rule_secrets(pipe, rep)
    rule_injection(pipe, rep)
    rule_secret_on_cli(pipe, rep)
    rule_access_token(pipe, rep)
    rule_gates(pipe, rep, hosting)
    rule_prod_branches(pipe, rep)
    rule_unpinned(pipe, rep)
    rule_pools(pipe, rep)
    rule_free_text_targets(pipe, rep)
    rule_security_steps(pipe, rep)
    rule_git(pipe, rep)
    rule_keyvault(pipe, rep)
    rule_housekeeping(pipe, rep)
    rule_context(pipe, rep)


# ---------------------------------------------------------------- discovery

PIPELINE_NAME = re.compile(r"(azure-pipelines.*\.ya?ml|.*\.azure-pipelines\.ya?ml|.*pipeline.*\.ya?ml)$", re.I)
PIPELINE_DIRS = (".azuredevops", ".azure-pipelines", ".pipelines", "pipelines", "pipeline-templates",
                 "azure-pipelines", "azure-templates", "build", "ci", "eng")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "bin", "obj", "__pycache__", ".github"}


def looks_like_pipeline(doc):
    root = doc.root
    if not isinstance(root, LMap):
        return False
    return any(k in root for k in ("stages", "jobs", "steps", "extends"))


def is_root_pipeline(doc):
    root = doc.root
    if not isinstance(root, LMap):
        return False
    return any(k in root for k in ("trigger", "pr", "schedules", "pool", "resources", "extends", "name")) or \
        os.path.basename(doc.path).lower().startswith("azure-pipelines")


def discover(paths, loader):
    files = []
    for path in paths:
        if os.path.isfile(path):
            files.append(os.path.abspath(path))
            continue
        for base, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            rel_parts = set(os.path.relpath(base, path).replace(os.sep, "/").lower().split("/"))
            in_pipeline_dir = bool(rel_parts & set(PIPELINE_DIRS))
            for name in sorted(names):
                if not name.lower().endswith((".yml", ".yaml")):
                    continue
                if PIPELINE_NAME.match(name) or in_pipeline_dir:
                    files.append(os.path.abspath(os.path.join(base, name)))
    seen, out = set(), []
    for f in files:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def run(paths, root=None, hosting="unknown"):
    paths = paths or ["."]
    if root is None:
        first = paths[0]
        root = first if os.path.isdir(first) else (os.path.dirname(os.path.abspath(first)) or ".")
        probe = os.path.abspath(root)
        while True:
            if os.path.isdir(os.path.join(probe, ".git")):
                root = probe
                break
            parent = os.path.dirname(probe)
            if parent == probe:
                break
            probe = parent
    loader = Loader(root)
    explicit = {os.path.abspath(p) for p in paths if os.path.isfile(p)}
    rep = Report()
    docs = [loader.load(f) for f in discover(paths, loader)]
    scanned, included = [], set()
    pipelines = []
    for doc in docs:
        if doc.error:
            line, problem = doc.error
            rep.add("PG-R09", "medium", doc, line,
                    f"This file is not valid YAML ({problem}), so the pipeline cannot run.",
                    "Fix the syntax. An unquoted `*` in a trigger is a common cause: write `'*'`.")
            scanned.append(doc.display)
            continue
        if not looks_like_pipeline(doc):
            continue
        if is_root_pipeline(doc) or doc.path in explicit:
            pipelines.append(Pipeline(doc, loader))
    for pipe in pipelines:
        for d in pipe.docs[1:]:
            included.add(d.path)
    # templates nobody includes are analysed on their own
    for doc in docs:
        if doc.error or not looks_like_pipeline(doc):
            continue
        if doc.path not in included and all(p.doc is not doc for p in pipelines):
            pipelines.append(Pipeline(doc, loader))
    for pipe in pipelines:
        if pipe.doc.path in included and pipe.doc.path not in explicit:
            continue
        scan_pipeline(pipe, rep, hosting)
        for d in pipe.docs:
            if d.display not in scanned:
                scanned.append(d.display)
    order = {s: i for i, s in enumerate(reversed(SEVERITIES))}
    rep.findings.sort(key=lambda f: (f["housekeeping"], order[f["severity"]], f["file"], f["line"], f["rule"]))
    rep.checks.sort(key=lambda c: (c["topic"], c["file"], c["line"]))
    return {"version": VERSION, "files": scanned, "findings": rep.findings, "checks": rep.checks,
            "not_covered": NOT_COVERED}


# ------------------------------------------------------------------- output


def summary(result):
    counts = {s: 0 for s in SEVERITIES}
    house = 0
    for f in result["findings"]:
        if f["housekeeping"]:
            house += 1
        else:
            counts[f["severity"]] += 1
    return counts, house


def to_text(result):
    out = []
    counts, house = summary(result)
    out.append(f"PipeGuard {result['version']}: {len(result['files'])} file(s) scanned")
    out.append("  " + ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITIES)) + f", {house} housekeeping")
    main = [f for f in result["findings"] if not f["housekeeping"]]
    if main:
        out.append("")
        out.append("FINDINGS")
    for f in main:
        out.append(f"  [{f['severity'].upper()}] {f['rule']} {f['title']}  ({f['file']}:{f['line']})")
        if f["quote"]:
            out.append(f"      > {f['quote']}")
        out.append(f"      {f['message']}")
        if f["fix"]:
            out.append(f"      Fix: {f['fix']}")
    hk = [f for f in result["findings"] if f["housekeeping"]]
    if hk:
        out.append("")
        out.append("HOUSEKEEPING")
        for f in hk:
            out.append(f"  {f['rule']} {f['title']}  ({f['file']}:{f['line']})")
    if result["checks"]:
        out.append("")
        out.append("TO CHECK IN AZURE DEVOPS")
        for c in result["checks"]:
            out.append(f"  [{c['topic']}] {c['message']}  ({c['file']}:{c['line']})")
    out.append("")
    out.append("Rules that need a human or Claude review: " + ", ".join(result["not_covered"]))
    return "\n".join(out)


def to_sarif(result):
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules = [{"id": rid, "name": rid.replace("-", ""), "shortDescription": {"text": title},
              "helpUri": "https://github.com/abirayedtn-source/pipeguard"}
             for rid, title in sorted(RULES.items())]
    results = []
    for f in result["findings"]:
        text = f["message"] + (f" Fix: {f['fix']}" if f["fix"] else "")
        results.append({
            "ruleId": f["rule"], "level": level[f["severity"]],
            "message": {"text": text},
            "properties": {"severity": f["severity"], "housekeeping": f["housekeeping"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": max(1, f["line"])}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "PipeGuard", "version": result["version"],
                                      "informationUri": "https://github.com/abirayedtn-source/pipeguard",
                                      "rules": rules}},
                  "results": results}],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pipeguard_scan", description="Audit Azure DevOps YAML pipelines.")
    parser.add_argument("paths", nargs="*", help="pipeline files or directories (default: current directory)")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                        help="exit with 1 when a finding at or above this level exists (default: high)")
    parser.add_argument("--hosting", choices=["github", "azure-repos", "unknown"], default="unknown",
                        help="where the repository lives; decides how pull request builds are judged")
    parser.add_argument("--root", help="repository root, used to resolve template paths")
    parser.add_argument("--output", help="write the report to this file instead of stdout")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)
    for path in args.paths:
        if not os.path.exists(path):
            parser.error(f"path not found: {path}")
    result = run(args.paths, root=args.root, hosting=args.hosting)
    if args.format == "json":
        text = json.dumps(result, indent=2)
    elif args.format == "sarif":
        text = json.dumps(to_sarif(result), indent=2)
    else:
        text = to_text(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    if args.fail_on != "none":
        threshold = SEVERITIES.index(args.fail_on)
        for f in result["findings"]:
            if not f["housekeeping"] and SEVERITIES.index(f["severity"]) >= threshold:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
