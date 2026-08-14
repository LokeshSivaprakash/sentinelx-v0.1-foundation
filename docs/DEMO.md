# SentinelX Demo Guide

This guide provides a repeatable end-to-end demonstration of SentinelX's security intelligence and controlled SOC automation workflow.

The demonstration follows a critical container vulnerability from event ingestion through detection, risk prioritization, investigation, SOC automation, remediation, verification, and incident resolution.

---

## Demo Environment

Start SentinelX from the project root:

    docker compose up -d

Verify the platform:

    docker compose ps

Expected services:

    api
    postgres
    neo4j

Open the API documentation:

    http://localhost:8000/docs

Open Neo4j Browser:

    http://localhost:7474

---

## Demo Scenario

We simulate a critical OpenSSL vulnerability affecting a production container image.

Example vulnerability:

    CVE-SOC-DEMO-2026-0001

Package:

    openssl

Installed version:

    3.0.0

Fixed version:

    3.0.1

Context:

    CVSS:              9.8
    Environment:       production
    Internet exposed:  true
    Asset criticality: critical
    Exploit available: true
    Patch available:   true

Expected result:

    Risk:     99
    Priority: P0
    Severity: critical

---

# 1. Ingest the Security Event

In Swagger, open:

    POST /v1/events

Use a new `event_id` for each demonstration run.

Example request:

    {
      "event_id": "demo-soc-event-001",
      "schema_version": "0.1",
      "source": "sentinelx-demo",
      "event_type": "vulnerability",
      "severity": "critical",
      "timestamp": "2026-08-13T21:00:00Z",
      "tenant_id": "local",
      "resource": {
        "id": "demo-api:1.0.0",
        "name": "demo-api",
        "type": "container_image"
      },
      "finding": {
        "id": "CVE-SOC-DEMO-2026-0001",
        "cvss": 9.8,
        "package": "openssl",
        "metadata": {},
        "fixed_version": "3.0.1",
        "installed_version": "3.0.0"
      },
      "evidence": [],
      "relationships": [],
      "metadata": {
        "asset_id": "prod-server-demo-01",
        "asset_name": "prod-server-demo-01",
        "service_id": "demo-api",
        "service_name": "demo-api",
        "environment": "production",
        "internet_exposed": true,
        "asset_criticality": "critical",
        "exploit_available": true,
        "patch_available": true
      },
      "raw_reference": null
    }

Expected response:

    202 Accepted

This confirms that SentinelX accepted the event.

---

# 2. Detection

The event is evaluated by the detection engine.

The critical event should produce four detections:

    DET-001
    DET-002
    DET-003
    DET-004

The rules represent:

    Critical internet-exposed vulnerability
    Critical exploitable vulnerability
    Critical asset vulnerability
    Exploitable vulnerability with patch

Open:

    GET /v1/detections/{resource_id}

Use:

    demo-api:1.0.0

Expected:

    detection_count: 4

---

# 3. Risk Prioritization

Open:

    GET /v1/intelligence/risk-prioritized

The demonstration event should be prioritized as:

    Risk score: 99
    Priority:    P0

The risk is driven by:

    High CVSS
    Production environment
    Internet exposure
    Critical asset
    Known exploit

This demonstrates contextual prioritization rather than CVSS-only ranking.

---

# 4. Incident Correlation

The detections are correlated into an incident.

Open:

    POST /v1/incidents/correlate/{resource_id}

Use:

    demo-api:1.0.0

Expected:

    Severity: critical
    Status:   open
    Detection count: 4

Copy the returned:

    incident_id

You will use this identifier for the remaining steps.

---

# 5. Neo4j Security Intelligence

The event creates relationships in the Neo4j security graph.

The graph represents:

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

Open:

    GET /v1/intelligence/attack-path/{cve}

Use:

    CVE-SOC-DEMO-2026-0001

Show the returned path:

    Asset
    -> Service
    -> Container Image
    -> Package
    -> Vulnerability

Then open:

    GET /v1/intelligence/blast-radius/{cve}

Show:

    affected_assets
    affected_services
    affected_images

This demonstrates why a vulnerability is more than an isolated CVE.

---

# 6. Incident Investigation

Open:

    GET /v1/incidents/{incident_id}/investigation

Use the incident ID from the correlation step.

The investigation view combines:

    Incident
    Risk
    Detections
    Security Events
    Attack Path
    Blast Radius
    Recommended Actions
    Remediation Intelligence
    SOC Automation State

This is the main analyst investigation view.

---

# 7. SOC Playbook

The critical vulnerability automatically triggers the SOC playbook:

    critical-vulnerability-response

The playbook generates:

    create_incident
    assign_analyst
    request_containment
    request_patch

Open:

    GET /v1/soc/actions/{incident_id}

Expected:

    count: 4

Each action should initially be:

    status: pending

---

# 8. SOC Queue

Open:

    GET /v1/soc/queue

The queue exposes pending actions for analyst review.

Example:

    Priority: P0
    Playbook: critical-vulnerability-response
    Action:   request_patch
    Status:   pending

This represents the analyst work queue.

---

# 9. Analyst Approval

Select a pending action.

Open:

    PATCH /v1/soc/actions/{action_id}

Move the action from:

    pending
    ->
    approved

Example:

    {
      "status": "approved",
      "result": "SOC analyst approved the remediation request."
    }

Expected:

    status: approved

---

# 10. Start the Action

Move the same action to:

    running

Example:

    {
      "status": "running",
      "result": "Remediation workflow started."
    }

Expected:

    status: running

---

# 11. Complete the Action

Complete the action after the remediation workflow has finished.

Example:

    {
      "status": "completed",
      "result": "openssl upgraded from 3.0.0 to 3.0.1 and deployment verified."
    }

Expected:

    status: completed

The action metadata should record:

    execution_completed: true

---

# 12. Complete the Patch Action

For the `request_patch` action, use the same controlled lifecycle:

    pending
    ->
    approved
    ->
    running
    ->
    completed

Example completion result:

    openssl upgraded from 3.0.0 to 3.0.1
    and deployment verified.

---

# 13. Remediation Verification

Open:

    POST /v1/incidents/{incident_id}/verify-remediation

Example:

    {
      "package": "openssl",
      "previous_version": "3.0.0",
      "remediated_version": "3.0.1",
      "verification_methods": [
        "package_version_check",
        "vulnerability_rescan",
        "deployment_verification"
      ]
    }

Expected:

    verification.status = verified

This step is important because completing a SOC action does not automatically mean that remediation has been verified.

---

# 14. Incident Lifecycle

Update the incident through the analyst workflow.

### Open -> Investigating

    PATCH /v1/incidents/{incident_id}

Request:

    {
      "status": "investigating",
      "analyst_notes": "SOC analyst started investigation of the critical vulnerability."
    }

### Investigating -> Contained

    {
      "status": "contained",
      "analyst_notes": "Containment and remediation actions completed."
    }

### Contained -> Resolved

Only after remediation verification has been recorded:

    {
      "status": "resolved",
      "analyst_notes": "Remediation verified across the affected production resource.",
      "resolution": "Upgraded openssl from 3.0.0 to 3.0.1, verified deployment, and completed vulnerability rescan."
    }

Expected final state:

    status: resolved

---

# 15. Final Investigation View

Run:

    GET /v1/incidents/{incident_id}/investigation

The final incident should demonstrate:

    Risk level:        critical
    Risk score:        99
    Priority:          P0
    Severity:          critical
    Status:            resolved

And should contain:

    4 detections
    Attack path
    Blast radius
    Remediation verification
    SOC automation history
    Analyst notes
    Resolution

---

# 16. What This Demonstrates

The complete demonstration shows that SentinelX can:

    Ingest security events
        |
        v
    Detect security conditions
        |
        v
    Persist detections
        |
        v
    Prioritize risk
        |
        v
    Correlate incidents
        |
        v
    Enrich with security graph intelligence
        |
        v
    Calculate attack paths
        |
        v
    Calculate blast radius
        |
        v
    Generate remediation guidance
        |
        v
    Trigger SOC automation
        |
        v
    Track analyst actions
        |
        v
    Verify remediation
        |
        v
    Resolve the incident

---

# 17. Interview Talking Point

A concise explanation of the project:

"SentinelX is a security intelligence and controlled SOC automation platform I built around a vulnerability-to-resolution workflow. A security event is evaluated by deterministic detection rules, prioritized using contextual risk factors, correlated into an incident, enriched through a Neo4j security graph for attack-path and blast-radius analysis, and then routed into controlled SOC playbooks. Analysts can approve and track remediation actions, and an incident cannot be resolved until remediation is independently verified."

---

# 18. Key Technical Talking Points

### Why PostgreSQL?

PostgreSQL stores transactional application state:

    Events
    Detections
    Incidents
    SOC Actions
    Remediation Metadata

### Why Neo4j?

Neo4j represents relationships that are difficult to understand in flat records:

    Asset
    -> Service
    -> Container
    -> Package
    -> Vulnerability

This allows SentinelX to answer questions such as:

    Which assets are affected?
    Which services are exposed?
    Which container images contain the vulnerable package?
    What is the potential blast radius?

### Why Controlled SOC Automation?

SentinelX does not automatically execute destructive production actions.

Instead, it creates auditable actions that move through:

    pending
    ->
    approved
    ->
    running
    ->
    completed

This provides automation while keeping analyst control over sensitive response operations.

### Why Remediation Verification?

An action being completed does not necessarily prove that the vulnerability is fixed.

SentinelX therefore separates:

    Action completion
        from
    Remediation verification

Only verified remediation allows the incident to move to `resolved`.

---

# 19. Demo Cleanup

After completing the demonstration, optionally inspect the generated data.

PostgreSQL:

    docker compose exec postgres psql -U sentinelx -d sentinelx

Neo4j:

    http://localhost:7474

API:

    http://localhost:8000/docs

---

# 20. Recommended Demo Order

For a 5–10 minute presentation, use this sequence:

    1. Architecture
    2. Submit critical vulnerability event
    3. Show four detections
    4. Show P0 risk
    5. Show Neo4j attack path
    6. Show blast radius
    7. Show incident investigation
    8. Show SOC queue
    9. Approve a SOC action
    10. Complete the patch action
    11. Verify remediation
    12. Resolve the incident

The key story is:

    Detect
      ->
    Prioritize
      ->
    Investigate
      ->
    Automate
      ->
    Remediate
      ->
    Verify
      ->
    Resolve
