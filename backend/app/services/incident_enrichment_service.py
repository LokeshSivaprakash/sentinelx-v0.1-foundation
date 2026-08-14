from app.services.neo4j_service import (
    get_attack_path,
    get_blast_radius,
)


def enrich_incident_from_cve(
    cve: str,
) -> dict:
    """
    Gather Neo4j intelligence for an incident CVE.
    """

    attack_path = get_attack_path(cve)

    blast_radius = get_blast_radius(cve)

    affected_assets = {
        result["asset_id"]
        for result in blast_radius
        if result.get("asset_id")
    }

    affected_services = {
        result["service_id"]
        for result in blast_radius
        if result.get("service_id")
    }

    affected_images = {
        result["image_id"]
        for result in blast_radius
        if result.get("image_id")
    }

    return {
        "cve": cve,
        "attack_path_count": len(attack_path),
        "blast_radius": {
            "affected_assets": len(
                affected_assets
            ),
            "affected_services": len(
                affected_services
            ),
            "affected_images": len(
                affected_images
            ),
        },
        "attack_path": attack_path,
        "blast_radius_results": blast_radius,
    }