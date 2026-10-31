## Summary

<!-- One sentence describing what this PR does. -->

## Changes

<!-- List the key changes: new files, modified behaviour, etc. -->

- 

## Checklist

- [ ] `python -m pytest -q` passes locally (no failures)
- [ ] No `.env`, secrets, API keys, or tokens committed
- [ ] No changes to frozen contracts (`shared/contracts.py` enums/models, existing routes, reason codes) — or if changed, both owners have approved
- [ ] If contracts changed: `shared/examples/` updated and `docs/openapi.json` regenerated (`python scripts/export_openapi.py`)
- [ ] `docs/FRONTEND_INTEGRATION.md` updated if any route or model changed
- [ ] `docs/decisions.md` updated for any non-obvious design choice
- [ ] New routes have tests in `backend/tests/`

## Testing notes

<!-- Describe how you tested this, any edge cases, etc. -->

## Related issues / context

<!-- Link issues or mention teammates if coordination needed. -->
