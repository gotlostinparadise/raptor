# Delivering features to `main`

A repeatable, guard-railed flow for landing work on `main` without (a) committing
the local-only config override, (b) disturbing a concurrent session sharing the
checkout, or (c) reding a CI gate that could have been caught locally.

## One-time setup (per clone)

```bash
git config core.hooksPath .githooks
```

This activates two guards under `.githooks/`:

- **`pre-commit`** — refuses to commit `core/llm/config.py` (it carries a
  "Do NOT commit" local `max_cost` override) and obvious secret-bearing files.
- **`pre-push`** — runs the fast `check_command_metadata.py` CI gate before a
  push (enforced when the repo venv is present; advisory-skip from a bare
  worktree).

The hooks are the mechanical backstop; the discipline below is the flow.

## The flow

1. **Never commit to `main` directly.** Branch per feature:
   `git switch -c feat/<short-name> main`.

2. **Stage explicit paths — never `git add -A` / `git add .`.** Blind staging is
   how the `config.py` override, a peer's in-progress files, or stray artifacts
   leak into a commit. Add the files you actually changed, then verify:
   ```bash
   git add <paths...>
   git status              # confirm ONLY intended files are staged
   git diff --cached --stat
   ```
   The pre-commit hook will hard-block `core/llm/config.py` even if it slips in.

3. **Run the gate locally** before merging:
   ```bash
   .venv/bin/python -m pytest core packages -q          # unit gate (integration/slow deselected)
   .venv/bin/python .github/scripts/check_command_metadata.py
   ```
   Browser / DOM-XSS and other `@pytest.mark.integration` tests are deselected
   by default; they run in CI via the nightly **`browser-integration`** job
   (installs Chromium) and the nightly **`slow-integration`** job.

4. **Land on `main` via a pull request** (the default — CI runs on it and the
   merge is atomic on GitHub's side, so it never races a concurrent push):
   ```bash
   git push origin feat/<short-name>
   gh pr create --base main --head feat/<short-name> --fill
   gh pr merge --merge --delete-branch          # once CI is green
   ```
   `origin` is the owner's fork (`gotlostinparadise/raptor`); confirm with
   `git remote -v` — never push to an `upstream`/`gadievron` remote without an
   explicit request. A direct `git push origin main` (fast-forward only) works
   for a solo checkout, but with another session active it *will* lose the push
   race — prefer the PR.

## When another session shares the checkout

If `git worktree list` shows the main checkout on someone else's branch, do
**not** `git switch` in it — that yanks HEAD out from under them. Deliver from an
isolated worktree instead:

```bash
git worktree add -b feat/<short-name> ../raptor-wt-<short-name> main
# reconstruct your changes in ../raptor-wt-<short-name>, commit, gate
git branch -f main feat/<short-name>     # allowed: main isn't checked out anywhere
git push origin main feat/<short-name>
git worktree remove ../raptor-wt-<short-name>
```

`git branch -f main <branch>` only fast-forwards when `main` is an ancestor of
`<branch>` (always true for a branch cut from `main`); re-check `git rev-parse
main` right before, in case the peer advanced it — if it moved, rebase your
branch onto the new `main` first.
