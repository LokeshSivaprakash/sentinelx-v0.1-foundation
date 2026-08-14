# SentinelX

SentinelX is an open-source security intelligence and SOC automation platform for detecting, prioritizing, investigating, and responding to security events.

It combines:

- FastAPI for the API layer
- PostgreSQL for event, detection, incident, and automation persistence
- Neo4j for security relationship analysis
- Detection rules for vulnerability-driven triage
- Risk prioritization
- Incident correlation and investigation
- Remediation intelligence and verification
- Controlled SOC automation and analyst workflows

---

## Architecture

    SentinelX
        |
        v
    Security Event
        |
        v
    +----------------+
    | Event Ingest   |
    |    FastAPI     |
    +-------+--------+
            |
        +---+---+
        |       |
        v       v
    PostgreSQL  Neo4j
        |       |
        |       +--> Attack Path
        |       |
        |       +--> Blast Radius
        |
        +------------------+
                           |
                           v
                    Detection Engine
                           |
                           v
                  Incident Correlation
                           |
                           v
                    Risk Prioritization
                           |
                           v
                  Incident Investigation
                           |
                    +------+------+
                    |             |
                    v             v
              Remediation      SOC Automation
              Intelligence      / Playbooks
                    |             |
                    v             v
              Verification    Action Queue
                    |             |
                    +------+------+
                           |
                           v
                    Analyst Workflow
                           |
             OPEN -> INVESTIGATING
                           |
                           v
                       CONTAINED
                           |
                           v
                        RESOLVED

---

## Core Workflow

SentinelX processes security events through the following workflow:

    Security Event
         |
         v
    Event Persistence
         |
         v
    Detection Rules
         |
         v
    Detection Persistence
         |
         v
    Incident Correlation
         |
         v
    Risk Prioritization
         |
         v
    Neo4j Intelligence
         |
         +--> Attack Path
         |
         +--> Blast Radius
         |
         v
    Incident Investigation
         |
         v
    SOC Playbook
         |
         v
    Automation Actions
         |
         v
    Remediation
         |
         v
    Remediation Verification
         |
         v
    Incident Resolution

---

## Detection Engine

The current detection engine contains four vulnerability-focused rules.

### DET-001 — Critical Internet-Exposed Vulnerability

Triggers when:

- the event contains a finding
- severity is critical
- the resource is internet exposed

Risk score:

    95

### DET-002 — Critical Exploitable Vulnerability

Triggers when:

- the event contains a finding
- severity is critical
- an exploit is available

Risk score:

    100

### DET-003 — Critical Asset Vulnerability

Triggers when:

- a vulnerability finding exists
- the affected asset is marked critical

Risk score:

    90

### DET-004 — Exploitable Vulnerability With Patch

Triggers when:

- exploit is available
- patch is available

Risk score:

    85

---

## Risk Prioritization

SentinelX uses a weighted risk model with a normalized score from 0 to 100.

| Factor | Weight |
|---|---:|
| CVSS | 50 |
| Known exploit | 20 |
| Internet exposure | 15 |
| Critical asset | 10 |
| Production environment | 5 |

Priority levels:

| Score | Priority |
|---:|---|
| >= 97 | P0 |
| >= 85 | P1 |
| >= 65 | P2 |
| < 65 | P3 |

Example:

    CVSS 9.8
    Production
    Internet exposed
    Critical asset
    Known exploit

    Risk score = 99
    Priority   = P0

---

## Neo4j Security Intelligence

SentinelX builds a security graph using relationships such as:

    Asset
      |
      +-- RUNS --> Service
                     |
                     +-- USES --> ContainerImage
                                    |
                                    +-- CONTAINS --> Package
                                                       |
                                                       +-- HAS_VULNERABILITY
                                                                |
                                                                v
                                                           Vulnerability

The graph supports:

- attack path analysis
- blast radius analysis
- affected asset identification
- affected service identification
- affected container image identification
- exploit and exposure context

### Attack Path

Identifies the infrastructure path connecting:

    Asset
    -> Service
    -> Container Image
    -> Package
    -> Vulnerability

### Blast Radius

Identifies how broadly a vulnerability affects:

- assets
- services
- container images

---

## Incident Management

Incidents move through a controlled lifecycle:

    open
      |
      v
    investigating
      |
      v
    contained
      |
      v
    resolved

Invalid transitions are rejected.

Resolution is also gated by remediation verification.

An incident cannot be resolved unless remediation verification has been recorded.

---

## Incident Investigation

The investigation endpoint combines:

- incident state
- risk score
- security events
- detections
- CVE intelligence
- attack paths
- blast radius
- recommended actions
- analyst notes
- remediation information
- SOC automation state

This creates a single investigation view for analysts.

---

## Remediation Intelligence

SentinelX generates structured remediation guidance including:

- package
- current version
- target version
- urgency
- remediation action
- remediation rationale
- verification steps
- rollback and contingency guidance

Example:

    openssl
    3.0.0 -> 3.0.1
    urgency: immediate
    action: patch

---

## Remediation Verification

Verification is recorded against the incident and can include:

- package_version_check
- vulnerability_rescan
- deployment_verification
- configuration_check
- manual_validation

A verified remediation is required before the incident can be resolved.

---

## SOC Automation

SentinelX includes a controlled SOC automation layer.

For a critical vulnerability, the current playbook is:

    critical-vulnerability-response
        |
        +--> create_incident
        |
        +--> assign_analyst
        |
        +--> request_containment
        |
        +--> request_patch

Actions are tracked in an audit table and move through:

    pending
       |
       v
    approved
       |
       v
    running
       |
       v
    completed

Additional states include:

- rejected
- failed

SentinelX intentionally uses controlled action requests rather than automatically executing destructive production actions.

---

## SOC Queue

The SOC queue exposes pending automation actions for analyst review.

Example:

    P0
    critical-vulnerability-response
    request_patch
    pending

Analysts can approve, execute, complete, reject, or fail actions through the API.

---

## PostgreSQL

The application persists the following major entities:

    security_events
    security_detections
    security_incidents
    security_automation_actions

PostgreSQL is responsible for transactional application state and auditability.

---

## API

The API is provided by FastAPI.

### Health

    GET /health

### Events

    POST /v1/events

### Detections

    POST /v1/detections/evaluate
    GET  /v1/detections
    GET  /v1/detections/{resource_id}

### Incidents

    POST  /v1/incidents/correlate/{resource_id}
    GET   /v1/incidents/{resource_id}
    GET   /v1/incidents/{incident_id}/investigation
    PATCH /v1/incidents/{incident_id}
    POST  /v1/incidents/{incident_id}/verify-remediation

### Intelligence

    GET /v1/intelligence/critical-vulnerabilities
    GET /v1/intelligence/risk-prioritized
    GET /v1/intelligence/correlate/{cve}
    GET /v1/intelligence/attack-path/{cve}
    GET /v1/intelligence/blast-radius/{cve}
    GET /v1/intelligence/remediation/{cve}

### SOC

    GET   /v1/soc/queue
    GET   /v1/soc/actions/{incident_id}
    PATCH /v1/soc/actions/{action_id}

Interactive API documentation is available at:

    http://localhost:8000/docs

---

## Project Structure

    sentinelx-v0.1-foundation/
    |
    +-- backend/
    |   +-- app/
    |   |   +-- main.py
    |   |   +-- init_db.py
    |   |
    |   |   +-- db/
    |   |   |   +-- neo4j.py
    |   |   |   +-- postgres.py
    |   |
    |   |   +-- models/
    |   |   |   +-- db_models.py
    |   |   |   +-- detections.py
    |   |   |   +-- events.py
    |   |   |   +-- incidents.py
    |   |
    |   |   +-- services/
    |   |       +-- correlation_service.py
    |   |       +-- detection_service.py
    |   |       +-- event_service.py
    |   |       +-- incident_enrichment_service.py
    |   |       +-- incident_investigation_service.py
    |   |       +-- incident_service.py
    |   |       +-- intelligence_service.py
    |   |       +-- neo4j_service.py
    |   |       +-- remediation_service.py
    |   |       +-- remediation_verification_service.py
    |   |       +-- risk_service.py
    |   |       +-- soc_action_service.py
    |   |       +-- soc_automation_service.py
    |   |
    |   +-- tests/
    |       +-- test_health.py
    |
    +-- docs/
    +-- .github/
    +-- docker-compose.yml
    +-- .env.example
    +-- README.md

---

## Environment Configuration

SentinelX uses environment variables for database and service credentials.

Create your local environment file from the example:

    Copy-Item .env.example .env

Then update the values in `.env` for your environment.

Example:

    POSTGRES_DB=sentinelx
    POSTGRES_USER=sentinelx
    POSTGRES_PASSWORD=your-postgres-password

    DATABASE_URL=postgresql+psycopg://sentinelx:your-postgres-password@localhost:5432/sentinelx

    NEO4J_URI=bolt://localhost:7687
    NEO4J_USER=neo4j
    NEO4J_PASSWORD=your-neo4j-password

The `.env` file is intentionally excluded from version control.

Never commit production credentials, passwords, API keys, or other secrets to the repository.

---

## Running With Docker

### Start the Platform

From the project root:

    docker compose up -d

Check services:

    docker compose ps

Expected services:

    api
    postgres
    neo4j

### Access the API

    http://localhost:8000

### Swagger

    http://localhost:8000/docs

### Neo4j Browser

    http://localhost:7474

### PostgreSQL

    localhost:5432

---

## PostgreSQL Access

The PostgreSQL username, password, and database are configured through `.env`.

Connect from Docker:

    docker compose exec postgres psql -U sentinelx -d sentinelx

List tables:

    \dt

Expected application tables:

    security_events
    security_detections
    security_incidents
    security_automation_actions

---

## Neo4j Access

Neo4j credentials are configured through `.env`.

The Neo4j Browser is available at:

    http://localhost:7474

---

## Running Tests

From the backend directory:

    cd backend
    pytest

For syntax checks:

    python -m py_compile app/main.py

For individual modules:

    python -m py_compile app/services/detection_service.py
    python -m py_compile app/services/incident_service.py
    python -m py_compile app/services/soc_action_service.py

---

## End-to-End Demonstration

A complete SentinelX security scenario can be demonstrated as:

1. Submit a critical vulnerability event
2. Persist the event
3. Trigger four detection rules
4. Persist detections
5. Create and correlate the incident
6. Calculate P0 risk
7. Enrich through Neo4j
8. Identify attack path
9. Calculate blast radius
10. Generate remediation guidance
11. Trigger the critical vulnerability SOC playbook
12. Review SOC actions
13. Approve actions
14. Run actions
15. Complete containment and patch actions
16. Verify remediation
17. Move the incident through:
    open
    -> investigating
    -> contained
    -> resolved

---

## Example Scenario

Example vulnerability:

    CVE-E2E-2026-0001

Example package:

    openssl 3.0.0

Fixed version:

    3.0.1

Example risk context:

    CVSS:              9.8
    Internet exposed: true
    Exploit available: true
    Asset criticality: critical
    Environment:       production

Example priority:

    Risk:     99
    Priority: P0

The same CVE can then be traced through the Neo4j graph to determine the broader blast radius.

---

## Technology Stack

- Python
- FastAPI
- Pydantic
- SQLAlchemy
- PostgreSQL
- Neo4j
- Docker
- Docker Compose
- Pytest

---

## Project Status

SentinelX currently provides a working security intelligence and controlled SOC automation foundation including:

- event ingestion
- event idempotency
- detection
- detection persistence
- contextual risk prioritization
- incident correlation
- incident investigation
- PostgreSQL persistence
- Neo4j security graph intelligence
- attack path analysis
- blast radius analysis
- remediation intelligence
- remediation verification
- incident lifecycle management
- SOC playbooks
- SOC action queue
- controlled action lifecycle
- analyst workflows
- Docker-based deployment
- API and Swagger documentation
- end-to-end SOC workflow

The project is currently positioned as a v0.1 foundation for continued expansion.

---

## Roadmap

Potential future extensions include:

- additional detection rules
- SIEM integrations
- external vulnerability feeds
- real-time alerting
- ticketing integrations
- Slack and Teams notifications
- analyst assignment automation
- cloud asset integrations
- Kubernetes runtime telemetry
- richer authentication and authorization
- RBAC
- multi-tenant isolation
- scheduled rescans
- automated vulnerability verification
- production notification channels
- analyst dashboard UI
- broader SOAR playbook library

---

## License

Add the project's chosen license here before publishing the repository.

---

## Author

**Lokesh Sivaprakash**

SentinelX is developed as an open-source security engineering project focused on security intelligence, automation, incident response, and application/container security.
