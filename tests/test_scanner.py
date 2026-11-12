"""Tests for the PipeGuard scanner. Run with: python -m unittest discover -s tests"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SCANNER = os.path.join(REPO, "pipeguard", "scripts", "pipeguard_scan.py")
FIXTURES = os.path.join(HERE, "fixtures")
sys.path.insert(0, os.path.dirname(SCANNER))
import pipeguard_scan as pg  # noqa: E402


def scan(path, hosting="unknown"):
    return pg.run([path], root=os.path.dirname(path), hosting=hosting)


def rules(result):
    return {f["rule"] for f in result["findings"]}


class RuleFixtures(unittest.TestCase):
    """Every rule fires on its bad fixture and stays quiet on its good one."""

    def test_each_rule(self):
        covered = sorted(d for d in os.listdir(FIXTURES) if d.startswith("PG-"))
        self.assertEqual(sorted(pg.RULES) , sorted(covered + ["PG-S07"]),
                         "every scanner rule needs a fixture folder (PG-S07 is reported as a check)")
        for rule in covered:
            hosting = "github" if rule == "PG-S14" else "unknown"
            with self.subTest(rule=rule, kind="bad"):
                bad = scan(os.path.join(FIXTURES, rule, "bad.azure-pipelines.yml"), hosting)
                self.assertIn(rule, rules(bad))
            with self.subTest(rule=rule, kind="good"):
                good = scan(os.path.join(FIXTURES, rule, "good.azure-pipelines.yml"), hosting)
                self.assertNotIn(rule, rules(good))

    def test_findings_point_at_real_lines(self):
        for rule in sorted(d for d in os.listdir(FIXTURES) if d.startswith("PG-")):
            path = os.path.join(FIXTURES, rule, "bad.azure-pipelines.yml")
            with open(path) as fh:
                lines = fh.read().splitlines()
            for f in scan(path, "github")["findings"]:
                with self.subTest(rule=f["rule"], file=rule):
                    self.assertTrue(1 <= f["line"] <= len(lines))
                    if f["quote"]:
                        self.assertEqual(f["quote"], lines[f["line"] - 1].strip()[:200])


class FalsePositives(unittest.TestCase):
    def test_placeholder_is_not_critical(self):
        path = os.path.join(HERE, "_tmp_placeholder.azure-pipelines.yml")
        with open(path, "w") as fh:
            # Built at run time: a literal all-zero sample token is itself rejected by secret scanners.
            sample = "dapi" + "0" * 32
            fh.write(f"trigger: none\nvariables:\n  DATABRICKS_TOKEN: {sample}\nsteps:\n- script: echo hi\n")
        try:
            found = [f for f in scan(path)["findings"] if f["rule"] == "PG-S01"]
            self.assertEqual([f["severity"] for f in found], ["low"])
        finally:
            os.remove(path)

    def test_public_identifiers_are_not_secrets(self):
        good = scan(os.path.join(FIXTURES, "PG-S01", "good.azure-pipelines.yml"))
        self.assertNotIn("PG-S01", rules(good))


class Structure(unittest.TestCase):
    def test_invalid_yaml_is_reported_not_raised(self):
        result = scan(os.path.join(FIXTURES, "special", "invalid.azure-pipelines.yml"))
        self.assertEqual(rules(result), {"PG-R09"})
        self.assertEqual(result["findings"][0]["line"], 2)

    def test_local_template_is_followed(self):
        result = scan(os.path.join(FIXTURES, "special", "with-template.azure-pipelines.yml"))
        hits = [f for f in result["findings"] if f["rule"] == "PG-S05"]
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]["file"].endswith("templates/publish-steps.yml"))
        self.assertEqual(hits[0]["line"], 2)

    def test_self_hosted_pool_is_a_check(self):
        result = scan(os.path.join(FIXTURES, "special", "self-hosted.azure-pipelines.yml"))
        self.assertIn("Self-hosted agents", {c["topic"] for c in result["checks"]})

    def test_manual_validation_counts_as_gate_but_resume_is_flagged(self):
        result = scan(os.path.join(FIXTURES, "special", "manual-gate.azure-pipelines.yml"))
        s05 = [f for f in result["findings"] if f["rule"] == "PG-S05"]
        self.assertEqual([(f["severity"], f["line"]) for f in s05], [("medium", 13)])

    def test_pr_builds_depend_on_hosting(self):
        path = os.path.join(FIXTURES, "PG-S14", "bad.azure-pipelines.yml")
        self.assertIn("PG-S14", rules(scan(path, "github")))
        unknown = scan(path, "unknown")
        self.assertNotIn("PG-S14", rules(unknown))
        self.assertIn("Pull request builds", {c["topic"] for c in unknown["checks"]})
        azure = scan(path, "azure-repos")
        self.assertNotIn("PG-S14", rules(azure))

    def test_demo_pipeline(self):
        result = scan(os.path.join(REPO, "examples", "vulnerable-pipeline.yml"), "github")
        self.assertEqual(rules(result), {"PG-S01", "PG-S02", "PG-S03", "PG-S04", "PG-S05", "PG-S06",
                                         "PG-S10", "PG-S14", "PG-R01", "PG-C01"})


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, SCANNER, *args], capture_output=True, text=True)

    def test_exit_codes(self):
        bad = os.path.join(FIXTURES, "PG-S05", "bad.azure-pipelines.yml")
        good = os.path.join(FIXTURES, "PG-S05", "good.azure-pipelines.yml")
        self.assertEqual(self.run_cli(bad).returncode, 1)
        self.assertEqual(self.run_cli(bad, "--fail-on", "critical").returncode, 0)
        self.assertEqual(self.run_cli(bad, "--fail-on", "none").returncode, 0)
        self.assertEqual(self.run_cli(good).returncode, 0)
        self.assertEqual(self.run_cli("does-not-exist.yml").returncode, 2)

    def test_housekeeping_never_fails_the_build(self):
        bad = os.path.join(FIXTURES, "PG-C01", "bad.azure-pipelines.yml")
        self.assertEqual(self.run_cli(bad, "--fail-on", "low").returncode, 0)

    def test_json_and_sarif_are_valid(self):
        bad = os.path.join(FIXTURES, "PG-S06", "bad.azure-pipelines.yml")
        data = json.loads(self.run_cli(bad, "--format", "json").stdout)
        self.assertTrue(data["findings"])
        sarif = json.loads(self.run_cli(bad, "--format", "sarif").stdout)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "PipeGuard")
        ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            self.assertIn(res["ruleId"], ids)
            self.assertIn(res["level"], {"error", "warning", "note"})
            self.assertGreaterEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_directory_scan(self):
        data = json.loads(self.run_cli(FIXTURES, "--format", "json", "--fail-on", "none").stdout)
        self.assertGreater(len(data["files"]), 30)


if __name__ == "__main__":
    unittest.main()
