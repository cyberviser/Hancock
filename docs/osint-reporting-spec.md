# OSINT Reporting Implementation Spec

## Purpose

This spec adds a defensive OSINT reporting layer to Hancock for CISO and SOC use. It builds on the existing geolocation and enrichment flows in [collectors/osint_geolocation.py](/home/oai/Hancock/collectors/osint_geolocation.py:1), the multi-mode chat surface in [hancock_agent.py](/home/oai/Hancock/hancock_agent.py:1), and the Python CLI in [clients/python/hancock_cli.py](/home/oai/Hancock/clients/python/hancock_cli.py:1).

The goal is not offensive recon. The goal is evidence-backed exposure assessment for owned assets, approved consulting scope, and internal risk reporting.

## Scope

### In Scope
- Normalize analyst-provided evidence into a typed report model.
- Generate Markdown, JSON, and later HTML reports for `ciso`, `soc`, and `joint` audiences.
- Correlate passive findings with confidence, ownership, and control mappings.
- Enforce guardrails for authorization, redaction, and source provenance.

### Out of Scope
- Unapproved target discovery.
- Credential hunting, dark-web collection, or active probing by default.
- Offensive automation or attack-path generation against third-party assets.

## Implemented / Planned Files

- `collectors/osint_report_models.py`
  - Landed in this change. Dataclasses validate report metadata, scope, findings, evidence, recommendations, and diagrams.
- `collectors/osint_report_builder.py`
  - Landed in this change. Reads evidence JSON, validates guardrails, builds report objects, and renders Markdown.
- `collectors/osint_guardrails.py`
  - Landed in this change. Handles source citation checks, low-value PII masking, duplicate collapse, and unsafe-option rejection.
- `schemas/osint_report.schema.json`
  - Landed in this change. Canonical JSON report contract.
- `templates/osint_report_template.md`
  - Landed in this change. CISO/SOC report structure for Markdown authoring.
- `examples/osint_report.dev.json`
  - Landed in this change. Developer config example with safe defaults.

## Data Model

The canonical model lives in [schemas/osint_report.schema.json](/home/oai/Hancock/schemas/osint_report.schema.json:1). Core entities:

### `report_metadata`
- `title`
- `target`
- `classification`
- `generated_at`
- `analyst`
- `report_profile`
- `tool_version`

### `engagement`
- `requester`
- `business_owner`
- `authorization_reference`
- `objective`
- `report_profile`

### `scope`
- `in_scope`
- `out_of_scope`
- `collection_constraints`
- `source_policy`

### `assets`
- `asset_id`
- `asset_type`
- `value`
- `owner`
- `criticality`

### `findings`
- `id`
- `title`
- `severity`
- `summary`
- `asset_refs`
- `evidence_refs`
- `confidence`
- `risk_score`
- `mitre_attack`
- `nist_controls`
- `status`

### `evidence`
- `id`
- `type`
- `source_name`
- `source_url`
- `retrieved_at`
- `claim`
- `sensitivity`
- `raw_artifact_path`

### `recommendations`
- `immediate`
- `thirty_day`
- `long_term`

## CLI Design

### Prototype Developer Entry Point

```bash
python -m collectors.osint_report_builder \
  --config examples/osint_report.dev.json \
  --evidence data/osint/evidence.json \
  --output reports/example-osint.md
```

### Implemented Commands

- `build`
  - Validate config and evidence, then generate report output.
- `validate`
  - Validate a report or evidence bundle against schema and guardrails.
- `render`
  - Convert a normalized report JSON file to Markdown or HTML.
- `summarize`
  - Produce audience-specific summaries: `ciso`, `soc`, `legal`, `exec`.

### Planned Make Targets

```make
osint-report:
	$(PYTHON) -m collectors.osint_report_builder build --config $(CONFIG) --evidence $(EVIDENCE) --output $(OUT)

osint-validate:
	$(PYTHON) -m collectors.osint_report_builder validate --config $(CONFIG) --evidence $(EVIDENCE)
```

These are still planned; the Python module now exists, but the Makefile has not been updated yet.

## Report Generator Pipeline

1. **Load Inputs**
   - Config, evidence bundle, optional asset inventory, optional ownership manifest.
2. **Run Guardrails**
   - Require authorization reference.
   - Reject disallowed source classes.
   - Apply redaction policy.
3. **Normalize Evidence**
   - Assign stable `EVID-*` IDs.
   - Collapse duplicates by source URL + claim fingerprint.
   - Preserve raw artifact pointers for auditability.
4. **Correlate**
   - Group findings by asset, owner, and impact domain.
   - Flag contradictions when sources disagree.
   - Compute confidence from source count, freshness, and agreement.
5. **Score**
   - Severity from exploitability, exposure breadth, and asset criticality.
   - Executive score from highest-risk findings, not simple averaging.
6. **Render**
   - JSON as source of truth.
   - Markdown from the template.
   - HTML as a later conversion step.

## Guardrails

Guardrails should be code-enforced, not just documented.

### Required
- `authorization_reference` must be present.
- `source_url` and `retrieved_at` are required for every evidence item.
- `source_url` must be `https` outside lab mode and must not point to localhost or private network hosts.
- `report_profile` must be one of `ciso`, `soc`, or `joint`.
- `allow_active_collection` defaults to `false`.
- Every finding must cite at least one evidence item and meet `guardrails.min_confidence`.

### Default Safe Behavior
- Redact low-value PII by default.
- Disallow credential harvesting and dark-web/forum scraping modules.
- Require `lab_mode=true` for any synthetic or sample data flow.
- Fail closed when citations are missing.

### Developer Escape Hatches

Escape hatches are allowed only for local development and must be obvious in output:

- `lab_mode`
- `debug`
- `save_intermediates`
- `fail_on_missing_citation=false`
- `min_confidence`

Every non-default unsafe option should force a banner in the rendered report:

`WARNING: Generated with non-default developer settings. Not for production distribution.`

## User Options for Dev

The example config in [examples/osint_report.dev.json](/home/oai/Hancock/examples/osint_report.dev.json:1) should drive the first implementation.

Useful options:
- `profile`
- `outputs.markdown`
- `outputs.json`
- `render.redact_pii`
- `render.include_social_summary`
- `enrichment.geoip`
- `enrichment.threat_intel`
- `guardrails.allowed_source_hosts`
- `guardrails.min_confidence`
- `guardrails.allow_active_collection`
- `dev.strict_schema_validation`
- `dev.save_intermediates`
- `dev.sample_limit`
- `dev.debug`

## API Surface

After the CLI lands, the REST layer can expose:

- `POST /v1/osint/report/build`
- `POST /v1/osint/report/validate`
- `POST /v1/osint/report/render`

These should follow the same request/response style used in [docs/openapi.yaml](/home/oai/Hancock/docs/openapi.yaml:1).

## Test Plan

Add:

- `tests/test_osint_report_schema.py`
  - Schema validity and required-field coverage.
- `tests/test_osint_guardrails.py`
  - Unsafe config rejection and redaction behavior.
- `tests/test_osint_report_builder.py`
  - Confidence scoring, contradiction handling, and Markdown rendering.

Minimum checks:
- Missing citation fails validation.
- Unauthorized config fails validation.
- Duplicate evidence collapses deterministically.
- Rendered Markdown includes all required sections from the template.

## Delivery Order

1. Land schema, template, example config, builder, guardrails, and tests.
2. Expand scoring, contradiction handling, and HTML rendering.
3. Add Make targets and sample fixtures.
4. Add REST endpoints and OpenAPI docs.
5. Add downstream UI and workflow integration.
