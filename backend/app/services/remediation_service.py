from app.services.intelligence_service import (
    get_critical_vulnerabilities,
)


def _build_remediation(
    vulnerability: dict,
) -> dict:
    """
    Build structured remediation guidance for a vulnerability.
    """

    cve = vulnerability.get("cve")
    package = vulnerability.get("package")
    current_version = vulnerability.get("version")
    metadata = vulnerability.get("metadata") or {}

    fixed_version = vulnerability.get(
        "fixed_version"
    )

    # ---------------------------------------------------------
    # Determine urgency
    # ---------------------------------------------------------

    if (
        vulnerability.get("cvss", 0) >= 9.0
        and metadata.get("exploit_available") is True
        and metadata.get("internet_exposed") is True
    ):
        urgency = "immediate"

    elif (
        vulnerability.get("cvss", 0) >= 9.0
        or metadata.get("exploit_available") is True
    ):
        urgency = "high"

    else:
        urgency = "standard"

    # ---------------------------------------------------------
    # Determine remediation action
    # ---------------------------------------------------------

    if (
        metadata.get("patch_available") is True
        and fixed_version
    ):
        action = "patch"

        primary_action = (
            f"Upgrade {package} from "
            f"{current_version} to {fixed_version}."
        )

    elif metadata.get("patch_available") is True:
        action = "patch"

        primary_action = (
            f"Apply the available security patch "
            f"for {package}."
        )

    else:
        action = "mitigate"

        primary_action = (
            f"Apply compensating controls for "
            f"{package} until a patch is available."
        )

    # ---------------------------------------------------------
    # Reasons
    # ---------------------------------------------------------

    reasons = []

    if vulnerability.get("cvss", 0) >= 9.0:
        reasons.append(
            "critical CVSS severity"
        )

    if metadata.get(
        "internet_exposed"
    ) is True:
        reasons.append(
            "internet-exposed resource"
        )

    if metadata.get(
        "exploit_available"
    ) is True:
        reasons.append(
            "known exploit available"
        )

    if metadata.get(
        "asset_criticality"
    ) == "critical":
        reasons.append(
            "critical production asset"
        )

    if metadata.get(
        "environment"
    ) == "production":
        reasons.append(
            "production environment"
        )

    # ---------------------------------------------------------
    # Verification steps
    # ---------------------------------------------------------

    verification_steps = [
        "Deploy the remediation to the affected resource.",
        "Verify the installed package version.",
        "Rescan the affected resource for the vulnerability.",
        "Confirm the vulnerability is no longer detected.",
    ]

    # ---------------------------------------------------------
    # Rollback / contingency
    # ---------------------------------------------------------

    rollback = [
        "If remediation causes service instability, "
        "rollback to the previous known-good deployment.",
        "Maintain compensating controls while remediation "
        "is being validated.",
    ]

    return {
        "cve": cve,
        "action": action,
        "urgency": urgency,
        "package": package,
        "current_version": current_version,
        "target_version": fixed_version,
        "primary_action": primary_action,
        "reason": reasons,
        "verification": verification_steps,
        "rollback": rollback,
    }


def get_remediation_for_cve(
    cve: str,
) -> dict:
    """
    Return remediation guidance for a specific CVE.
    """

    vulnerabilities = (
        get_critical_vulnerabilities()
    )

    matches = [
        item
        for item in vulnerabilities
        if item.get("cve") == cve
    ]

    if not matches:
        raise ValueError(
            f"No critical vulnerability found for CVE: {cve}"
        )

    remediation = [
        _build_remediation(item)
        for item in matches
    ]

    return {
        "cve": cve,
        "affected_instances": len(remediation),
        "remediation": remediation,
    }