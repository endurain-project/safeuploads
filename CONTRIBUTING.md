# Contributing to safeuploads
 
Thank you for considering contributing to safeuploads! Before diving in, please read these guidelines carefully. They exist to make the process sustainable for everyone.

## A Note on Maintainership
 
safeuploads is maintained by a single person in their spare time. This means review bandwidth is genuinely limited. Following these guidelines isn't bureaucracy, it's what allows contributions to actually get merged rather than sitting in a queue indefinitely.

## Before You Write Any Code
 
**Open an issue first.** For anything beyond a small bug fix, typo, or documentation improvement, please open an issue and wait for a response before writing code. This takes minutes and can save you hours of work on something that won't be merged because it conflicts with planned direction, existing work, or project scope.
 
If an issue already exists, comment on it to signal your intent so work isn't duplicated.

## Pull Request Size — The Most Important Rule
 
**Keep PRs small and focused on a single concern.**
 
As a rule of thumb:
 
- **Target under 300 lines changed** (excluding lock files and generated code)
- **One PR = one thing.** Don't bundle a bug fix with a refactor with a new feature
- If your change is naturally large (e.g. a new integration), break it into a chain of smaller PRs that can each be reviewed and merged independently

PRs that are too large to review efficiently will be asked to be split before they receive a review. This isn't a judgment on the quality of the work, it's a maintainability constraint.
 
**Excluded from the line count:** `uv.lock` and other generated or vendored files.

## How to Contribute
 
### Bug Fixes

- Check if an issue already exists before opening a new one
- Include clear steps to reproduce in the issue
- Small, targeted fixes are the fastest path to a merge

### Documentation

- Always welcome and rarely requires prior discussion
- Improvements to the docs site, inline code comments, and the README all count
- Keep the same tone and structure as existing docs

### New Features

- **Always discuss in an issue first** — this is required, not optional
- Features that haven't been discussed and approved in an issue may be closed without review, regardless of quality

### Refactors and Code Quality

- Must be discussed in an issue first
- Pure refactor PRs (no behaviour change) are easiest to review. Keep them separate from feature or fix PRs
- Include a clear explanation of what improved and why


## Getting Started
 
1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/safeuploads.git
   ```
3. **Create a branch** and use a descriptive name:
   ```bash
   git checkout -b fix/nested-archive-depth
   # or
   git checkout -b feat/polyglot-signature-check
   ```
4. **Make your changes**, committing with clear messages following [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   fix(inspectors): bound nested archive depth
   feat(validators): add a polyglot signature check
   docs: update the integration checklist
   ```
   Commit subjects and PR titles are validated in CI; see `.agents/skills/conventional-commits/SKILL.md` for the allowed types and scopes.
5. **Run the checks** from the repository root (Python 3.13+, [uv](https://docs.astral.sh/uv/) and the system `libmagic`):
   ```bash
   uv sync --dev --extra fastapi
   uv run ruff check safeuploads tests examples
   uv run ruff format --check safeuploads tests examples
   uv run mypy
   uv run pytest
   ```
6. **Push and open a PR** against the `main` branch, filling in the PR template completely

## Response Time Expectations
 
Reviews may take days to weeks depending on availability. A PR sitting without a response is not a rejection. Please feel free to leave a polite ping after two weeks if there's been no activity.

## Thank You
 
Even small contributions make a real difference. Thank you for taking the time to improve safeuploads for everyone who uses it.