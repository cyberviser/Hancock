# Hancock Local Static Assessment

Hancock local static assessment is a review-first workflow for inspecting a local project tree without executing code, running scans, contacting external services, or uploading files.

It is designed for situations like reviewing a local `hermes-agent` checkout, dependency manifests, Docker/Nix configuration, CI workflows, and obvious high-risk code patterns before any dynamic testing is considered.

## Safety contract

The assessor is intentionally local and passive:

- Does not execute project code.
- Does not run shell commands.
- Does not scan networks.
- Does not contact external services.
- Does not upload files.
- Produces review guidance only.
- Preserves Hancock's authorized-scope-only guardrails.

## Usage

```bash
python hancock_static_assessor.py /path/to/project --format markdown
```

JSON output:

```bash
python hancock_static_assessor.py /path/to/project --format json
```

CI-style gates:

```bash
# Return 2 when high-severity findings exist.
python hancock_static_assessor.py /path/to/project --fail-on high

# Return 1 when medium or high findings exist.
python hancock_static_assessor.py /path/to/project --fail-on medium
```

Exclude additional generated trees:

```bash
python hancock_static_assessor.py /path/to/project --exclude generated --exclude vendor
```

## Built-in discovery

The assessor inventories common manifests and config files, including:

- `pyproject.toml`
- `requirements*.txt`
- `package.json`
- lockfiles
- `Dockerfile`
- Compose files
- `.env` / `.env.example`
- selected GitHub workflow files

Default excluded trees include:

- `.git`
- `.pytest_cache`
- `__pycache__`
- `.venv`, `venv`, `env`
- `node_modules`
- `dist`, `build`, `.next`, `.turbo`, `target`

## Built-in static rules

The first rule pack detects review-worthy patterns such as:

- Credential and secret key names.
- `eval`, `exec`, `os.system`, and `subprocess` usage.
- `shell=True`.
- `yaml.load`.
- `pickle.load` / `pickle.loads`.
- TLS verification disablement.
- `0.0.0.0` wide binds.
- `chmod 777`.
- root containers.
- GitHub Actions workflows that need pin review.

Findings are intentionally conservative and should be treated as review prompts, not proof of vulnerability.

## Example workflow for Hermes

```bash
cd /sandbox/.openclaw-data/workspace/hermes-agent
python /path/to/Hancock/hancock_static_assessor.py . --format markdown > /tmp/hancock-hermes-static-assessment.md
```

Recommended scope:

```text
Allowed:
- Static source review
- Dependency/config review
- Docker/Nix/CI review
- Local secret-pattern detection

Not allowed without separate approval:
- External network scanning
- Exploitation
- Credential attacks
- Persistence/evasion testing
- Destructive testing
- Uploading files or samples to third-party services
```

## Roadmap

Next improvements:

- SARIF export for GitHub code scanning.
- Rule IDs mapped to CWE, OWASP ASVS, and MITRE ATT&CK where appropriate.
- Configurable policy packs.
- Redaction-aware evidence snippets.
- Integration with Hancock's safe agentic orchestration planner.
