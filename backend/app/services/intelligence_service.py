from app.db.neo4j import driver


def get_critical_vulnerabilities() -> list[dict]:
    query = """
    MATCH (image:ContainerImage)-[:CONTAINS]->(package:Package)
          -[:HAS_VULNERABILITY]->(vulnerability:Vulnerability)
    MATCH (image)-[:RUNS_ON]->(asset:Asset)
    MATCH (image)-[:SERVES]->(service:Service)

    WHERE vulnerability.severity = "critical"

    RETURN
        asset.id AS asset,
        service.id AS service,
        image.name AS image,
        package.name AS package,
        package.version AS version,
        vulnerability.id AS cve,
        vulnerability.cvss AS cvss,
        vulnerability.fixed_version AS fixed_version,
        vulnerability.environment AS environment,
        vulnerability.internet_exposed AS internet_exposed,
        vulnerability.asset_criticality AS asset_criticality,
        vulnerability.exploit_available AS exploit_available,
        vulnerability.patch_available AS patch_available
    ORDER BY vulnerability.cvss DESC
    """

    with driver.session() as session:
        result = session.run(query)

        results = []

        for record in result:
            data = record.data()

            data["metadata"] = {
                "environment": data.pop("environment", None),
                "internet_exposed": data.pop("internet_exposed", None),
                "asset_criticality": data.pop("asset_criticality", None),
                "exploit_available": data.pop("exploit_available", None),
                "patch_available": data.pop("patch_available", None),
            }

            results.append(data)

        return results