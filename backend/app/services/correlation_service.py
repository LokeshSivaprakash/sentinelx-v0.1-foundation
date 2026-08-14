from app.db.neo4j import driver


def find_related_vulnerabilities(cve: str) -> list[dict]:
    query = """
    MATCH (image:ContainerImage)-[:CONTAINS]->(package:Package)
          -[:HAS_VULNERABILITY]->(vulnerability:Vulnerability)

    MATCH (image)-[:RUNS_ON]->(asset:Asset)

    MATCH (image)-[:SERVES]->(service:Service)

    WHERE vulnerability.id = $cve

    RETURN
        vulnerability.id AS cve,
        vulnerability.severity AS severity,
        vulnerability.cvss AS cvss,
        image.name AS image,
        package.name AS package,
        asset.id AS asset,
        service.id AS service
    """

    with driver.session() as session:
        result = session.run(
            query,
            {"cve": cve},
        )

        return [record.data() for record in result]