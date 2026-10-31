# Contributing to AgentGuard AI SOC

Thank you for your interest in contributing! This guide covers the collaboration workflow for the KODIKON 6.0 hackathon build.

---

## Repository Ownership

| Directory / Area | Owner |
|---|---|
| `backend/`, `mock_tool/`, `shared/`, `scripts/`, `docs/` | [@y0gish123](https://github.com/y0gish123) |
| `frontend/` | [@gaanavi](https://github.com/gaanavi) |
| `shared/contracts.py` (frozen) | **Both** — changes need approval from both owners |

---

## Branch Naming

| Prefix | When to use |
|---|---|
| `feature/*` | New functionality (e.g. `feature/ai-explanation-ui`) |
| `chore/*` | Maintenance, docs, CI (e.g. `chore/collab-setup`) |
| `fix/*` | Bug fixes (e.g. `fix/token-expiry-edge-case`) |
| `eval/*` | Experiment / evaluation scripts |

All branches target `main`. Never push directly to `main`.

---

## Pull Request Process

1. **Create a branch** from the latest `main`.
2. **Make small, focused commits** — one logical change per commit.
3. **Run tests before every commit:**
   ```powershell
   # PowerShell
   python -m pytest -q
   ```
   ```bash
   # bash
   python -m pytest -q
   ```
4. **Open a PR** into `main`. Fill in the PR template checklist.
5. **CI must be green** before merge. No force-merges.
6. **At least one review** from the other owner before merging (except hot-fixes during the 24-hour build window).

---

## Frozen Contracts

The following are **frozen** — do not change without written approval from both owners:

- All enum names and string values in `shared/contracts.py`
- All Pydantic model field names and types in `shared/contracts.py`
- All existing route paths and HTTP methods
- All `ReasonCode` values in `backend/policy/messages.py`

You may **add** new enums, models, routes, or reason codes after discussion.

---

## Security Rules

- **Never commit `.env`** or any real secrets, tokens, API keys, or credentials.
- `.env` is gitignored — copy `.env.example` to create your local `.env`.
- If you accidentally commit a secret: **stop, report it immediately** to both owners, and do not rewrite history without coordination.
- Event text and user-supplied data are **untrusted** — never eval, execute, or interpolate them outside the policy boundary.
- All simulated — never touch real accounts, hosts, or networks.

---

## Code Style

- **Python 3.11+**, typed, readable, small functions.
- **Pydantic v2** for all models — use `model_validate`, not `parse_obj`.
- **SQLAlchemy 2.x** ORM only — no raw SQL string interpolation.
- Cap string inputs at 2000 chars; cap request bodies at 1 MB.
- Use `hmac.compare_digest` for all HMAC comparisons. Never log tokens or secrets.

---

## Frontend ↔ Backend Contract

The frontend developer should read [`docs/FRONTEND_INTEGRATION.md`](docs/FRONTEND_INTEGRATION.md) for the full API contract. The backend developer should keep that document up to date whenever routes or models change.

---

## Questions

Open a GitHub Issue or message in the team channel. During the hackathon build window, communicate directly.
