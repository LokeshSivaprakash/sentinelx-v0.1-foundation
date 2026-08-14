from app.services.intelligence_service import (
    get_critical_vulnerabilities,
)

# ============================================================
# RISK WEIGHTS
# ============================================================

CVSS_WEIGHT = 50.0
EXPLOIT_WEIGHT = 20.0
INTERNET_EXPOSURE_WEIGHT = 15.0
CRITICAL_ASSET_WEIGHT = 10.0
PRODUCTION_WEIGHT = 5.0


def calculate_risk_score(
    item: dict,
) -> tuple[float, list[str]]:
    """
    Calculate a weighted vulnerability risk score.

    Final score: 0-100.

    Factors:
        CVSS             -> 50%
        Exploit          -> 20%
        Internet exposure-> 15%
        Critical asset   -> 10%
        Production       -> 5%
    """

    risk_factors: list[str] = []

    # =========================================================
    # CVSS
    # =========================================================

    cvss = float(
        item.get("cvss") or 0
    )

    cvss = max(
        0.0,
        min(cvss, 10.0),
    )

    score = (
        cvss / 10.0
    ) * CVSS_WEIGHT

    # =========================================================
    # Metadata
    # =========================================================

    metadata = (
        item.get("metadata")
        or {}
    )

    # =========================================================
    # Production environment
    # =========================================================

    if metadata.get(
        "environment"
    ) == "production":

        score += PRODUCTION_WEIGHT

        risk_factors.append(
            "production_environment"
        )

    # =========================================================
    # Internet exposure
    # =========================================================

    if metadata.get(
        "internet_exposed"
    ) is True:

        score += INTERNET_EXPOSURE_WEIGHT

        risk_factors.append(
            "internet_exposed"
        )

    # =========================================================
    # Critical asset
    # =========================================================

    if metadata.get(
        "asset_criticality"
    ) == "critical":

        score += CRITICAL_ASSET_WEIGHT

        risk_factors.append(
            "critical_asset"
        )

    # =========================================================
    # Known exploit
    # =========================================================

    if metadata.get(
        "exploit_available"
    ) is True:

        score += EXPLOIT_WEIGHT

        risk_factors.append(
            "known_exploit"
        )

    # =========================================================
    # No patch
    # =========================================================
    #
    # We intentionally do not add a separate weight here.
    #
    # Patch availability is important context, but adding
    # another score component would push the model beyond
    # the intended 100-point weighting.
    #
    # It can be incorporated into remediation priority later.
    # =========================================================

    if metadata.get(
        "patch_available"
    ) is False:

        risk_factors.append(
            "no_patch_available"
        )

    # =========================================================
    # Normalize
    # =========================================================

    score = max(
        0.0,
        min(score, 100.0),
    )

    return (
        round(score, 2),
        risk_factors,
    )


def _get_priority(
    risk_score: float,
) -> str:
    """
    Convert 0-100 risk score into remediation priority.
    """

    if risk_score >= 90:
        return "P0"

    if risk_score >= 75:
        return "P1"

    if risk_score >= 50:
        return "P2"

    return "P3"


def get_prioritized_vulnerabilities() -> list[dict]:
    """
    Return vulnerabilities ordered by weighted risk.
    """

    vulnerabilities = (
        get_critical_vulnerabilities()
    )

    prioritized: list[dict] = []

    for item in vulnerabilities:

        risk_score, risk_factors = (
            calculate_risk_score(item)
        )

        priority = _get_priority(
            risk_score
        )

        prioritized.append(
            {
                **item,
                "risk_score": risk_score,
                "priority": priority,
                "risk_factors": risk_factors,
            }
        )

    prioritized.sort(
        key=lambda item: (
            item["risk_score"],
            item.get("cvss") or 0,
        ),
        reverse=True,
    )

    return prioritized