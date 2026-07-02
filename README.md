<h1 align="center">Glev Agent Skills</h1>
<p align="center">
  Reusable <a href="https://agentskills.io">Agent Skills</a> for working with the
  Glev platform — installable into any project with the <code>skills</code> CLI.
</p>

---

This repo is a **home for many skills**. Each skill is a self-contained folder
under `skills/` (a `SKILL.md` plus optional `reference/` docs and `scripts/`), the
layout the [`skills` CLI](https://github.com/vercel-labs/skills) discovers and
installs into `.claude/skills/`.

## Install

Install **all** skills into the current project:

```bash
npx skills add Glev-ai/skills
```

Install **one** skill:

```bash
npx skills add Glev-ai/skills --skill glev-continuous-autofix
```

> `npx skills` writes the skill files under `.agents/skills/<name>/` and
> **symlinks them into `.claude/skills/<name>`** — which is where Claude Code
> discovers skills (start a new Claude Code session to pick them up). If your
> project has no `.claude/` directory yet, create one first so the symlink lands.
> Add `-g` for user scope (available across all your projects).

## Skills

| Skill | What it does |
|---|---|
| [`glev-continuous-autofix`](skills/glev-continuous-autofix/) | Given a PR reference, downloads that PR's Glev Continuous CI artifact via `gh`, parses the per-finding verdicts + remediation, applies surgical fixes to the checked-out branch, and stops at a diff for review (never auto-commits). |
| [`glev-application-security-trend-report`](skills/glev-application-security-trend-report/) | Runs a month-by-month OpenGrep security audit over a repo's git history (OpenGrep runs via Docker), isolating the findings *newly introduced* each month and rendering a self-contained, Glev-branded HTML trend report to `tmp/glev/report.html`. |

## Repository layout

```
skills/
  <skill-name>/
    SKILL.md          # frontmatter (name, description, allowed-tools) + procedure
    reference/        # optional: schemas, playbooks the skill reads on demand
    scripts/          # optional: bundled helper scripts the skill runs
.github/workflows/
  ci.yml              # lints SKILL.md frontmatter + shellchecks bundled scripts
```

## Adding a new skill

1. `mkdir -p skills/<name>/{reference,scripts}` (drop the empty ones you don't need).
2. Write `skills/<name>/SKILL.md` with YAML frontmatter — **required:** `name`
   (must match the folder, lowercase-kebab), `description` (a routing rule: when
   should Claude reach for this skill). Optional: `allowed-tools`, `argument-hint`,
   `disable-model-invocation`.
   - Scaffold a starting point with `npx skills init`.
3. Keep heavy detail in `reference/*.md` (loaded on demand) so `SKILL.md` stays
   the lean procedure. Put runnable helpers in `scripts/` and mark them `+x`.
4. Add a row to the **Skills** table above.
5. `ci.yml` validates the frontmatter and shellchecks the scripts on every PR.

## Compatibility

Built to the open **Agent Skills** standard, so the skills work with any tool that
supports it (Claude Code, Cursor, Cline, Codex, …). A Claude Code **plugin
marketplace** channel (`.claude-plugin/marketplace.json`) is a planned phase-2
add — the current `skills/<name>/SKILL.md` layout is already plugin-compatible, so
it's a drop-in when we want it.

## License

[MIT](LICENSE) © Glev
