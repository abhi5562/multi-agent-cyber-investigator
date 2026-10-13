from src.tools.neo4j_client import Neo4jClient

class GraphQueries:
    
    def __init__(self, client: Neo4jClient):
        self._client = client

    def resolve_entity(self, name_or_id):
        """Retrieve Entities by their Name or ID"""

        value = _validate_non_empty_string(name_or_id, "name_or_id")
        query = """
            MATCH (entity)
            WHERE entity.id = $value
            OR toLower(entity.name) = toLower($value)
            RETURN entity.id AS id,
                labels(entity) AS labels,
                properties(entity) AS properties
            ORDER BY CASE WHEN entity.id = $value THEN 0 ELSE 1 END,
                    entity.id
            LIMIT 10
            """
        return self._client.execute_query(query, {"value": value})


    def expand_neighborhood(self, entity_id, max_hops=1, limit=50):
        """Find entities and relationships near an entity."""

        entity_id = _validate_non_empty_string(entity_id, "entity_id")

        query = f"""
        MATCH path = (start {{id: $entity_id}})-[*1..{max_hops}]-(neighbor)
        WHERE start <> neighbor
        RETURN length(path) AS hop_count,
               [node IN nodes(path) |
                   {{
                       id: node.id,
                       labels: labels(node),
                       properties: properties(node)
                   }}
               ] AS nodes,
               [edge IN relationships(path) |
                   {{
                       id: edge.id,
                       type: type(edge),
                       start_id: startNode(edge).id,
                       end_id: endNode(edge).id,
                       properties: properties(edge)
                   }}
               ] AS relationships
        ORDER BY hop_count
        LIMIT $limit
        """

        return self._client.execute_query(query, {"entity_id": entity_id, "limit": limit})

    def find_paths_to_critical_assets(self, entity_id, max_hops=4, limit=50):
        """Find paths from an entity to critical assets."""
        entity_id = _validate_non_empty_string(entity_id, "entity_id")

        query = f"""
        MATCH path = (start {{id: $entity_id}})-[*1..{max_hops}]-(asset:CriticalAsset)
        WHERE start <> asset
        RETURN asset.id AS critical_asset_id,
               asset.name AS critical_asset_name,
               length(path) AS hop_count,
               [node IN nodes(path) |
                   {{
                       id: node.id,
                       labels: labels(node),
                       properties: properties(node)
                   }}
               ] AS nodes,
               [edge IN relationships(path) |
                   {{
                       id: edge.id,
                       type: type(edge),
                       start_id: startNode(edge).id,
                       end_id: endNode(edge).id,
                       properties: properties(edge)
                   }}
               ] AS relationships
        ORDER BY hop_count, critical_asset_id
        LIMIT $limit
        """

        return self._client.execute_query(query, {"entity_id": entity_id, "limit": limit})

    def get_permissions(self, principal_id):
        """Find permissions assigned to a role or service account."""
        principal_id = _validate_non_empty_string(principal_id, "principal_id")

        query = """
        MATCH (principal {id: $principal_id})
              -[permission:HAS_PERMISSION_ON]->(asset)
        RETURN principal.id AS principal_id,
               labels(principal) AS principal_labels,
               permission.id AS relationship_id,
               permission.permission AS permission,
               asset.id AS asset_id,
               asset.name AS asset_name,
               labels(asset) AS asset_labels,
               properties(asset) AS asset_properties
        ORDER BY asset.id
        """

        return self._client.execute_query(query, {"principal_id": principal_id})

    def get_asset_permissions(self, asset_id):
        """Find who has permission on a critical asset."""
        asset_id = _validate_non_empty_string(asset_id, "asset_id")

        query = """
        MATCH (principal)-[permission:HAS_PERMISSION_ON]->
              (asset:CriticalAsset {id: $asset_id})
        RETURN principal.id AS principal_id,
               principal.name AS principal_name,
               labels(principal) AS principal_labels,
               permission.id AS relationship_id,
               permission.permission AS permission,
               asset.id AS asset_id,
               asset.name AS asset_name
        ORDER BY principal_id, relationship_id
        """

        return self._client.execute_query(query, {"asset_id": asset_id})

    def get_vulnerabilities(self, asset_id):
        """Find vulnerabilities linked to an asset."""

        asset_id = _validate_non_empty_string(asset_id, "asset_id")

        query = """
        MATCH (asset {id: $asset_id})
              -[association:HAS_VULNERABILITY]->(vulnerability:Vulnerability)
        RETURN asset.id AS asset_id,
               asset.name AS asset_name,
               labels(asset) AS asset_labels,
               association.id AS relationship_id,
               vulnerability.id AS vulnerability_id,
               properties(vulnerability) AS vulnerability_properties
        ORDER BY vulnerability.id
        """

        return self._client.execute_query(query, {"asset_id": asset_id})


#Helper Method
def _validate_non_empty_string(value, field_name):
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{field_name} must be a non-empty string")

    return value.strip()