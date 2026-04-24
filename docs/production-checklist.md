# Production Readiness Checklist

Use this checklist before promoting Hancock to a production environment.

---

## Infrastructure

- [ ] Container image built from the production `Dockerfile` (non-root `hancock` user, Python 3.11-slim)
- [ ] Image scanned for CRITICAL/HIGH CVEs — no unresolved findings (`trivy image hancock:latest`)
- [ ] Image published to a private registry or `ghcr.io/cyberviser/hancock` with a pinned semver tag (not `latest`)
- [ ] Health check endpoint (`GET /health`) validated — returns `200` before traffic is accepted
- [ ] Graceful shutdown configured — `deploy/graceful_shutdown.py` active, `terminationGracePeriodSeconds: 30`

## Configuration & Secrets

- [ ] All secrets stored in the platform secrets manager (AWS Secrets Manager, Kubernetes Secrets, Fly secrets) — never in environment files or source control
- [ ] `HANCOCK_LLM_BACKEND` set explicitly (`ollama`, `nvidia`, or `openai`) and aligned with your credential configuration
- [ ] `HANCOCK_API_KEYS` (preferred) or `HANCOCK_API_KEY` set to strong random value(s) if the API is publicly accessible
- [ ] `HANCOCK_WEBHOOK_SECRET` set if webhook integrations are enabled
- [ ] `LOG_LEVEL` set to `INFO` (not `DEBUG`) in production
- [ ] `.env` file excluded from the Docker image and source control (confirm via `.dockerignore`)

## Networking & Security

- [ ] HTTPS enforced — TLS termination at load balancer or ingress
- [ ] API authentication enabled (`HANCOCK_API_KEYS` / `HANCOCK_API_KEY`) for any publicly reachable instance
- [ ] Agentic route rate limits tuned: `HANCOCK_RATE_LIMIT_AGENTIC_PER_MINUTE` and `HANCOCK_RATE_LIMIT_AGENTIC_PER_HOUR`
- [ ] Firewall / security group restricts direct access to port `5000`; only the load balancer can reach it
- [ ] Kubernetes security context applied: `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities: drop: [ALL]`

## Scalability & Reliability

- [ ] Minimum 2 replicas deployed (no single point of failure)
- [ ] Horizontal Pod Autoscaler (HPA) configured — `deploy/k8s/hpa.yaml` scales 2–10 replicas on CPU ≥ 70% / memory ≥ 80%
- [ ] Rolling update strategy in place — `maxSurge: 1`, `maxUnavailable: 0`
- [ ] Resource requests and limits set on all containers (see `deploy/k8s/deployment.yaml`)
- [ ] Liveness and readiness probes configured pointing to `GET /health`

## Observability

- [ ] Prometheus scraping `GET /metrics` at 15 s intervals
- [ ] Grafana dashboard imported from `monitoring/grafana_dashboard.json`
- [ ] Alerting rules loaded from `monitoring/alerting_rules.yaml`
- [ ] Alerts routed to an on-call channel (Slack, PagerDuty, or email) via Alertmanager
- [ ] Structured JSON logging active (`monitoring/logging_config.py`)
- [ ] Log aggregation pipeline collecting container stdout (e.g., CloudWatch Logs, Loki, Datadog)
- [ ] Request-ID correlation headers propagated through all upstream services

## Performance

- [ ] Benchmark suite passes with p99 < 500 ms — `pytest tests/benchmark_suite.py`
- [ ] Load test completed at expected peak RPS with failure rate < 0.1% (`tests/load_test_locust.py`)
- [ ] Memory usage stable under sustained load (no growth trend visible via `docker stats` or Grafana)

## Testing & CI

- [ ] All unit tests passing on Python 3.10, 3.11, and 3.12 — `.github/workflows/test.yml`
- [ ] Integration and deployment tests passing — `pytest tests/test_integration_deployment.py`
- [ ] Security scans passing — Bandit, pip-audit, Trivy (`.github/workflows/security.yml`)
- [ ] No open CodeQL alerts at high or critical severity

## Pre-Deployment Validation

- [ ] Pre-flight checks pass — `python deploy/startup_checks.py`
- [ ] Smoke test against staging environment confirms `/health`, `/v1/agents`, and `/v1/chat` return expected responses
- [ ] Rollback plan documented — previous image tag noted; `helm rollback` or `kubectl rollout undo` command ready

## Post-Deployment

- [ ] Confirm all pods reach `Running` state and readiness probes pass
- [ ] Verify Prometheus is receiving metrics from the new deployment
- [ ] Confirm no new alerts firing in Alertmanager
- [ ] Tail logs for the first 5 minutes — `kubectl logs -f deploy/hancock` or `fly logs`
- [ ] Run a quick functional smoke test against the production endpoint
