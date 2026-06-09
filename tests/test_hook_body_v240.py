"""Behavioral tests for the planning-with-files injection logic (v3).

History: through v2.43 the UserPromptSubmit / PreToolUse / PreCompact hook
bodies were giant inline bash scalars embedded in the SKILL.md frontmatter, and
this file extracted and ran those scalars directly. v3 (build decision "hooks
become thin dispatchers") moved the logic into a versioned, testable script,
`scripts/inject-plan.sh`, and reduced the scalars to a self-discovery dispatch
pattern: try ``${CLAUDE_SKILL_DIR}/scripts/inject-plan.sh``, fall back to the two
known install paths, run it with a ``--context=`` flag, exit 0 silently if the
script is absent.

This file therefore has two halves:

  * DispatcherScalarShapeTests — parse the SKILL.md frontmatter and assert the
    scalar is a correct dispatcher (discovery paths present, no ``---`` literal
    that would collide with YAML, exits 0 silently when the target is missing).
  * InjectPlanBehaviorTests — run ``scripts/inject-plan.sh`` directly with
    ``CLAUDE_SKILL_DIR`` set, preserving every behavioral assertion the old
    scalar tests made (slug beats root, corrupt active_plan fall-through, legacy
    root, pretool injection, timestamp normalization, SHA cache populate, tamper
    block with inverted resolution order). The behavioral contract is unchanged;
    only the place the logic lives moved.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_SKILL = REPO_ROOT / "skills" / "planning-with-files" / "SKILL.md"
# The v3 scripts (inject-plan.sh and siblings) live only under the canonical
# skill dir; the top-level scripts/ mirror predates them. Point CLAUDE_SKILL_DIR
# here so the dispatch + sibling resolution (resolve-plan-dir.sh) both work.
SKILL_DIR = REPO_ROOT / "skills" / "planning-with-files"
INJECT_PLAN = SKILL_DIR / "scripts" / "inject-plan.sh"

# Match a single `command: "<bash>"` value inside the named hook event block.
HOOK_RE_TEMPLATE = r'{event}:\n(?:.*?\n)*?\s*command: "((?:[^"\\]|\\.)*)"'


def extract_hook_scalar(event_name: str) -> str:
    """Return the dispatcher scalar for the named hook event, fully unescaped."""
    text = CANONICAL_SKILL.read_text(encoding="utf-8")
    match = re.search(HOOK_RE_TEMPLATE.format(event=event_name), text)
    assert match, f"hook scalar for {event_name} not found in canonical SKILL.md"
    raw = match.group(1)
    # YAML flow-scalar escaping: \" for literal ", \\ for literal \.
    raw = raw.replace('\\"', '"').replace("\\\\", "\\")
    return raw


def have_sh() -> bool:
    return shutil.which("sh") is not None


class DispatcherScalarShapeTests(unittest.TestCase):
    """The inline scalars must be thin dispatchers, not the logic itself."""

    INJECT_EVENTS = ("UserPromptSubmit", "PreToolUse", "PreCompact")

    def test_inject_scalars_reference_inject_plan_script(self) -> None:
        for event in self.INJECT_EVENTS:
            scalar = extract_hook_scalar(event)
            self.assertIn(
                "${CLAUDE_SKILL_DIR}/scripts/inject-plan.sh",
                scalar,
                f"{event} scalar must dispatch to inject-plan.sh via CLAUDE_SKILL_DIR",
            )

    def test_inject_scalars_carry_both_fallback_paths(self) -> None:
        # Skill-only installs land at ~/.claude/skills/...; plugin installs land
        # at ~/.claude/plugins/marketplaces/.... The dispatcher must probe both.
        for event in self.INJECT_EVENTS:
            scalar = extract_hook_scalar(event)
            self.assertIn(
                "$HOME/.claude/skills/planning-with-files/scripts/inject-plan.sh",
                scalar,
                f"{event} scalar missing skill-only fallback path",
            )
            self.assertIn(
                "$HOME/.claude/plugins/marketplaces/planning-with-files/scripts/inject-plan.sh",
                scalar,
                f"{event} scalar missing plugin marketplace fallback path",
            )
            self.assertIn("head -1", scalar, f"{event} scalar must pick a single path")

    def test_inject_scalars_pass_distinct_context_flags(self) -> None:
        self.assertIn("--context=userprompt", extract_hook_scalar("UserPromptSubmit"))
        self.assertIn("--context=pretool", extract_hook_scalar("PreToolUse"))
        self.assertIn("--context=precompact", extract_hook_scalar("PreCompact"))

    def test_stop_scalar_dispatches_to_gate(self) -> None:
        # The Stop hook dispatches to the v3 gate (gate-stop.sh / check-complete
        # --gate), not inject-plan. Assert the same self-discovery shape.
        scalar = extract_hook_scalar("Stop")
        self.assertIn("gate-stop.sh", scalar)
        self.assertIn(
            "$HOME/.claude/skills/planning-with-files/scripts/gate-stop.sh", scalar
        )

    def test_no_triple_dash_literal_in_any_scalar(self) -> None:
        # The YAML-collision class: a literal `---` inside a command scalar can
        # break the skill-picker parse (Discussion #153, v2.38.1). The thin
        # dispatchers must never contain it.
        for event in ("UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "PreCompact"):
            scalar = extract_hook_scalar(event)
            self.assertNotIn("---", scalar, f"{event} scalar contains a literal '---'")

    @unittest.skipUnless(have_sh(), "sh not available on this platform")
    def test_dispatcher_exits_zero_silently_when_script_absent(self) -> None:
        # With no CLAUDE_SKILL_DIR and an empty HOME (no install on either known
        # path), the dispatcher must produce no output and exit 0 — never break
        # the agent loop.
        scalar = extract_hook_scalar("UserPromptSubmit")
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as fake_home:
            script = Path(tmp) / "_dispatch.sh"
            script.write_text(scalar, encoding="utf-8")
            env = os.environ.copy()
            env.pop("CLAUDE_SKILL_DIR", None)
            env["HOME"] = fake_home  # no install under here
            result = subprocess.run(
                ["sh", str(script)],
                cwd=tmp,
                text=True,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout.strip())


@unittest.skipUnless(have_sh(), "sh not available on this platform")
class InjectPlanBehaviorTests(unittest.TestCase):
    """Exercise scripts/inject-plan.sh directly, the way the dispatcher does.

    Every assertion here was made by the old scalar-extraction tests. The
    behavioral contract must not weaken: only the invocation path changed.
    """

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="pwf-inject-"))
        # SHA cache now lives under XDG_CACHE_HOME/pwf-sha (security rec 2: moved
        # off world-writable /tmp). Give each test a private cache + HOME.
        self.cache_dir = self.tmp / "_xdg_cache"
        self.cache_dir.mkdir()
        self.home_dir = self.tmp / "_home"
        self.home_dir.mkdir()
        self.env = os.environ.copy()
        self.env["CLAUDE_SKILL_DIR"] = str(SKILL_DIR)
        self.env["XDG_CACHE_HOME"] = str(self.cache_dir)
        self.env["HOME"] = str(self.home_dir)
        self.env.pop("PLAN_ID", None)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, context: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sh", str(INJECT_PLAN), f"--context={context}"],
            cwd=str(self.tmp),
            text=True,
            capture_output=True,
            env=self.env,
            check=False,
        )

    def test_inject_plan_script_exists(self) -> None:
        self.assertTrue(INJECT_PLAN.exists(), f"missing {INJECT_PLAN}")

    def test_slug_plan_beats_root_task_plan(self) -> None:
        # When both a slug plan and a legacy root plan exist, slug-mode wins.
        plan_dir = self.tmp / ".planning" / "2026-05-21-slug-target"
        plan_dir.mkdir(parents=True)
        slug_marker = "SLUG-PLAN-CONTENT-MARKER"
        root_marker = "ROOT-PLAN-DECOY-MARKER"
        (plan_dir / "task_plan.md").write_text(f"# {slug_marker}\n", encoding="utf-8")
        (plan_dir / "progress.md").write_text("# progress\n", encoding="utf-8")
        (self.tmp / "task_plan.md").write_text(f"# {root_marker}\n", encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text(
            "2026-05-21-slug-target\n", encoding="utf-8"
        )

        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(slug_marker, result.stdout, "slug plan content must be injected")
        self.assertNotIn(root_marker, result.stdout, "root plan must not leak through")

    def test_legacy_root_only_still_works(self) -> None:
        # No .planning/ at all, just a root task_plan.md.
        (self.tmp / "task_plan.md").write_text("# Legacy Root Plan\n", encoding="utf-8")
        (self.tmp / "progress.md").write_text("# progress\n", encoding="utf-8")
        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Legacy Root Plan", result.stdout)
        self.assertIn("ACTIVE PLAN", result.stdout)

    def test_no_plan_anywhere_silent_exit_zero(self) -> None:
        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout.strip())

    def test_corrupt_active_plan_falls_through_to_newest(self) -> None:
        # Garbage (whitespace-only) in .active_plan must not break the hook; it
        # falls through to the newest valid plan dir.
        plan_dir = self.tmp / ".planning" / "2026-05-21-real"
        plan_dir.mkdir(parents=True)
        (plan_dir / "task_plan.md").write_text("# Real Plan\n", encoding="utf-8")
        (plan_dir / "progress.md").write_text("# progress\n", encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text("   \n\n   \n", encoding="utf-8")
        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Real Plan", result.stdout, "must fall through to newest valid plan")

    def test_sha_cache_populates_after_attested_fire(self) -> None:
        # An attested injection writes a cache entry under XDG_CACHE_HOME/pwf-sha
        # so subsequent fires can skip the sha256 step. The cache moved off /tmp
        # to a user-private dir (security rec 2); the 2-line mtime+SHA shape is
        # preserved.
        plan_dir = self.tmp / ".planning" / "2026-05-21-cached"
        plan_dir.mkdir(parents=True)
        plan_content = "# Plan with attestation\nphase 1\n"
        (plan_dir / "task_plan.md").write_bytes(plan_content.encode("utf-8"))
        (plan_dir / "progress.md").write_text("# progress\n", encoding="utf-8")
        digest = hashlib.sha256(plan_content.encode("utf-8")).hexdigest()
        (plan_dir / ".attestation").write_text(digest, encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text(
            "2026-05-21-cached\n", encoding="utf-8"
        )

        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(f"Plan-SHA256: {digest}", result.stdout)
        cache_root = self.cache_dir / "pwf-sha"
        self.assertTrue(
            cache_root.is_dir(),
            f"expected SHA cache at {cache_root}, dir not created",
        )
        cache_entries = list(cache_root.iterdir())
        self.assertTrue(cache_entries, "expected at least one cache entry after attested fire")
        cached = cache_entries[0].read_text(encoding="utf-8").splitlines()
        self.assertEqual(2, len(cached), f"cache file malformed: {cached!r}")
        self.assertEqual(digest, cached[1])

    def test_tamper_still_blocks_with_inverted_order(self) -> None:
        # Inverted resolution order must not weaken tamper detection: a slug plan
        # whose content diverges from its attestation is blocked, body hidden.
        plan_dir = self.tmp / ".planning" / "2026-05-21-tamper"
        plan_dir.mkdir(parents=True)
        original = "# Approved Plan\nphase 1\n"
        (plan_dir / "task_plan.md").write_text(original, encoding="utf-8")
        (plan_dir / "progress.md").write_text("# progress\n", encoding="utf-8")
        digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
        (plan_dir / ".attestation").write_text(digest, encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text(
            "2026-05-21-tamper\n", encoding="utf-8"
        )

        # Now tamper.
        (plan_dir / "task_plan.md").write_text(original + "INJECTED LINE\n", encoding="utf-8")
        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("PLAN TAMPERED", result.stdout)
        self.assertIn(f"expected={digest}", result.stdout)
        self.assertNotIn("INJECTED LINE", result.stdout)

    def test_progress_tail_timestamps_normalized(self) -> None:
        # Sub-second + tz-suffix timestamps in the injected progress tail are
        # collapsed to a stable epoch-zero form so the KV-cache prefix stays warm
        # (legacy mode keeps the raw tail, only timestamps normalized).
        plan_dir = self.tmp / ".planning" / "2026-05-21-cache-hygiene"
        plan_dir.mkdir(parents=True)
        (plan_dir / "task_plan.md").write_text("# Plan\n", encoding="utf-8")
        progress = (
            "## Session 2026-05-21T19:15:42.317Z\n"
            "did some work at 2026-05-21T20:01:09Z\n"
            "and then more at 2026-05-21T21:30:37.000+02:00\n"
        )
        (plan_dir / "progress.md").write_text(progress, encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text(
            "2026-05-21-cache-hygiene\n", encoding="utf-8"
        )

        result = self._run("userprompt")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("T19:15:42", result.stdout)
        self.assertNotIn("T20:01:09", result.stdout)
        self.assertNotIn("T21:30:37", result.stdout)
        self.assertIn("T00:00:00", result.stdout)

    def test_pretooluse_injects_plan_data(self) -> None:
        # PreToolUse uses the same resolution chain and emits the plan head
        # wrapped in BEGIN/END delimiters.
        plan_dir = self.tmp / ".planning" / "2026-05-21-pretool"
        plan_dir.mkdir(parents=True)
        (plan_dir / "task_plan.md").write_text("# Pre Tool Plan\nphase 1\n", encoding="utf-8")
        (plan_dir / "progress.md").write_text("# progress\n", encoding="utf-8")
        (self.tmp / ".planning" / ".active_plan").write_text(
            "2026-05-21-pretool\n", encoding="utf-8"
        )

        result = self._run("pretool")
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("===BEGIN PLAN DATA===", result.stdout)
        self.assertIn("Pre Tool Plan", result.stdout)
        self.assertIn("===END PLAN DATA===", result.stdout)


if __name__ == "__main__":
    unittest.main()
