## Description
This PR hardens the local CI and repository hygiene around Hancock, fixes a real runtime/lint defect, and addresses a stale in-memory rate-limit cleanup bug in the API server.

## Type of Change
- [x] 🐛 Bug fix
- [ ] ✨ New feature
- [ ] 📝 Documentation update
- [ ] 🤖 Training data addition
- [x] 🔧 Refactor / cleanup

## Related Issue
Closes #

## Changes Made
- Fixed stale bucket eviction in the in-memory rate limiter so expired IP buckets are pruned instead of accumulating indefinitely.
- Added regression coverage for stale rate-limit bucket cleanup in the API test suite.
- Hardened GitHub Actions workflows:
- added `pull_request` coverage to Python CI
- updated `actions/setup-python` to `v5`
- enabled pip cache
- added a CI timeout
- reduced workflow permissions to `contents: read` where appropriate
- added deploy concurrency protection for Netlify
- Added `clients/nodejs/package-lock.json` to make Node installs reproducible and keep audit results stable.
- Updated `.gitignore` to ignore local Node install artifacts and pytest cache.
- Fixed a missing import of `OPENAI_IMPORT_ERROR_MSG` so lint passes cleanly.

## Testing
- [ ] Tested CLI mode
- [x] Tested API server (`/v1/chat`, `/v1/triage`, etc.)
- [x] Verified no secrets in committed files

### Validation Run
- `./.venv/bin/flake8 . --count --select=E9,F63,F7,F82 --exclude=.venv,__pycache__,data,docs --show-source --statistics`
- `./.venv/bin/pytest tests/ -v --tb=short`

## Checklist
- [x] My code follows the existing style
- [x] I have NOT committed `.env` or any API keys
- [x] All training data is from public, legally sourced knowledge bases
- [x] The agent's ethical guardrails remain intact
