from app.db.neo4j import driver
from app.models.events import SecurityEvent


def create_security_graph(event: SecurityEvent) -> None:
    if not event.finding:
        return

    resource = event.resource
    finding = event.finding
    metadata = event.metadata

    query = """
    MERGE (image:ContainerImage {id: $image_id})
    SET image.name = $image_name

    MERGE (package:Package {
        name: $package_name,
        version: $package_version
    })

    MERGE (vulnerability:Vulnerability {
        id: $vulnerability_id
    })

    SET vulnerability.severity = $severity,
        vulnerability.cvss = $cvss,
        vulnerability.fixed_version = $fixed_version,
        vulnerability.environment = $environment,
        vulnerability.internet_exposed = $internet_exposed,
        vulnerability.asset_criticality = $asset_criticality,
        vulnerability.exploit_available = $exploit_available,
        vulnerability.patch_available = $patch_available

    MERGE (image)-[:CONTAINS]->(package)

    MERGE (package)-[:HAS_VULNERABILITY]->(vulnerability)
    """

    parameters = {
        "image_id": resource.id,
        "image_name": resource.name,
        "package_name": finding.package,
        "package_version": finding.installed_version,
        "vulnerability_id": finding.id,
        "severity": event.severity,
        "cvss": finding.cvss,
        "fixed_version": finding.fixed_version,
        "environment": metadata.get("environment"),
        "internet_exposed": metadata.get("internet_exposed"),
        "asset_criticality": metadata.get("asset_criticality"),
        "exploit_available": metadata.get("exploit_available"),
        "patch_available": metadata.get("patch_available"),
    }

    with driver.session() as session:
        result = session.run(query, parameters)
        result.consume()

        # ---------------------------------------------------------
        # Asset / Service relationships from event.relationships
        # ---------------------------------------------------------

        for relationship in event.relationships:
            target_type = relationship.get("target_type")
            target_id = relationship.get("target_id")
            relationship_type = relationship.get("type")

            if not target_type or not target_id or not relationship_type:
                continue

            if target_type == "asset":
                target_label = "Asset"
            elif target_type == "service":
                target_label = "Service"
            else:
                continue

            relationship_query = f"""
            MATCH (image:ContainerImage {{id: $image_id}})
            MERGE (target:{target_label} {{id: $target_id}})
            MERGE (image)-[:{relationship_type.upper()}]->(target)
            """

            relationship_result = session.run(
                relationship_query,
                {
                    "image_id": resource.id,
                    "target_id": target_id,
                },
            )

            relationship_result.consume()

        # ---------------------------------------------------------
        # Asset -> Service -> ContainerImage graph
        # ---------------------------------------------------------

        asset_id = metadata.get("asset_id")
        asset_name = metadata.get("asset_name")

        service_id = metadata.get("service_id")
        service_name = metadata.get("service_name")

        if asset_id and service_id:
            infrastructure_query = """
            MATCH (image:ContainerImage {id: $image_id})

            MERGE (asset:Asset {id: $asset_id})
            SET asset.name = $asset_name,
                asset.environment = $environment,
                asset.internet_exposed = $internet_exposed,
                asset.criticality = $asset_criticality

            MERGE (service:Service {id: $service_id})
            SET service.name = $service_name

            MERGE (asset)-[:RUNS]->(service)

            MERGE (service)-[:USES]->(image)
            """

            infrastructure_parameters = {
                "image_id": resource.id,
                "asset_id": asset_id,
                "asset_name": asset_name or asset_id,
                "service_id": service_id,
                "service_name": service_name or service_id,
                "environment": metadata.get("environment"),
                "internet_exposed": metadata.get(
                    "internet_exposed"
                ),
                "asset_criticality": metadata.get(
                    "asset_criticality"
                ),
            }

            infrastructure_result = session.run(
                infrastructure_query,
                infrastructure_parameters,
            )

            infrastructure_result.consume()

    print(
        f"Neo4j graph created for "
        f"{finding.id} / {resource.id}"
    )


def get_attack_path(cve: str) -> list[dict]:
    query = """
    MATCH path =
        (asset:Asset)
        -[:RUNS]->
        (service:Service)
        -[:USES]->
        (image:ContainerImage)
        -[:CONTAINS]->
        (package:Package)
        -[:HAS_VULNERABILITY]->
        (vulnerability:Vulnerability)

    WHERE vulnerability.id = $cve

    RETURN
        asset.id AS asset_id,
        asset.name AS asset,
        service.id AS service_id,
        service.name AS service,
        image.id AS image_id,
        image.name AS image,
        package.name AS package,
        package.version AS version,
        vulnerability.id AS cve,
        vulnerability.severity AS severity,
        vulnerability.cvss AS cvss,
        vulnerability.fixed_version AS fixed_version,
        asset.environment AS environment,
        asset.internet_exposed AS internet_exposed,
        asset.criticality AS asset_criticality,
        vulnerability.exploit_available AS exploit_available,
        vulnerability.patch_available AS patch_available

    ORDER BY vulnerability.cvss DESC
    """

    with driver.session() as session:
        result = session.run(
            query,
            {"cve": cve},
        )

        return [
            {
                "asset_id": record["asset_id"],
                "asset": record["asset"],
                "service_id": record["service_id"],
                "service": record["service"],
                "image_id": record["image_id"],
                "image": record["image"],
                "package": record["package"],
                "version": record["version"],
                "cve": record["cve"],
                "severity": record["severity"],
                "cvss": record["cvss"],
                "fixed_version": record["fixed_version"],
                "environment": record["environment"],
                "internet_exposed": record["internet_exposed"],
                "asset_criticality": record["asset_criticality"],
                "exploit_available": record["exploit_available"],
                "patch_available": record["patch_available"],
            }
            for record in result
        ]

def get_blast_radius(cve: str) -> list[dict]:
    query = """
    MATCH
        (asset:Asset)
        -[:RUNS]->
        (service:Service)
        -[:USES]->
        (image:ContainerImage)
        -[:CONTAINS]->
        (package:Package)
        -[:HAS_VULNERABILITY]->
        (vulnerability:Vulnerability)

    WHERE vulnerability.id = $cve

    RETURN DISTINCT
        asset.id AS asset_id,
        asset.name AS asset,
        service.id AS service_id,
        service.name AS service,
        image.id AS image_id,
        image.name AS image,
        package.name AS package,
        package.version AS version,
        vulnerability.id AS cve,
        vulnerability.severity AS severity,
        vulnerability.cvss AS cvss,
        asset.environment AS environment,
        asset.internet_exposed AS internet_exposed,
        asset.criticality AS asset_criticality,
        vulnerability.exploit_available AS exploit_available,
        vulnerability.patch_available AS patch_available

    ORDER BY vulnerability.cvss DESC
    """

    with driver.session() as session:
        result = session.run(
            query,
            {"cve": cve},
        )

        return [
            {
                "asset_id": record["asset_id"],
                "asset": record["asset"],
                "service_id": record["service_id"],
                "service": record["service"],
                "image_id": record["image_id"],
                "image": record["image"],
                "package": record["package"],
                "version": record["version"],
                "cve": record["cve"],
                "severity": record["severity"],
                "cvss": record["cvss"],
                "environment": record["environment"],
                "internet_exposed": record["internet_exposed"],
                "asset_criticality": record["asset_criticality"],
                "exploit_available": record["exploit_available"],
                "patch_available": record["patch_available"],
            }
            for record in result
        ]