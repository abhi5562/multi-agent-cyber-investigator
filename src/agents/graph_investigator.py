from src.tools.graph_queries import GraphQueries
from langchain_openai import ChatOpenAI
from src.schema import GraphQueryPlan, AgentRequest, AgentName, EvidenceRecord, CandidatePath, GraphInvestigationResult, GraphQueryCall, GraphOperation
from langchain_core.messages import HumanMessage, SystemMessage
from src.prompts import GRAPH_QUERY_SYSTEM_PROMPT
import json
from typing import Any


class GraphInvestigator:
    def __init__(self, query_client: GraphQueries):
        self._query_client = query_client
        self._plan_model = ChatOpenAI(model="gpt-5.6").with_structured_output(GraphQueryPlan)

    def investigate(self, request: AgentRequest, completed_searches: set):
        if request.target_agent != AgentName.GRAPH_INVESTIGATOR:
            raise ValueError("GraphInvestigator requires request of type Graph_Investigator.")

        evidence: list[EvidenceRecord] = []
        candidate_paths: list[CandidatePath] = []
        discovered_entity_ids: list[str] = [] #Unique entity IDs discovered 
        unresolved_references: list[str] = [] #Entity IDs whose details are not found
        open_questions: list[str] = [] 
        resolved_entity_details = {} #Key entity ID, Value -> Graph Data for entity Id

        #If no entities are provided in the request
        if not request.entity_references:
            open_questions.append("Which graph entity should be investigated?")

        for index, reference in enumerate(request.entity_references, start=1):
            matches = self._query_client.resolve_entity(reference)
            evidence.append(
                EvidenceRecord(
                    evidence_id=f"resolve-entity-{index}",
                    source_operation="resolve_entity",
                    content={"reference": reference, "matches": matches}
                )
            )

            #If no matches are found, then add the reference to unresolved
            if not matches:
                unresolved_references.append(reference)
                open_questions.append(f"Which graph entity corresponds to {reference}?")
                continue

            for match in matches:
                entity_id = match["id"]
                resolved_entity_details[entity_id] = match

                #Add the entity id to discovered entities
                if entity_id not in discovered_entity_ids:
                    discovered_entity_ids.append(entity_id)

        #If none of the entity details are found
        if not resolved_entity_details:
            return GraphInvestigationResult(
                evidence=evidence,
                discovered_entity_ids=discovered_entity_ids,
                unresolved_entity_references=unresolved_references,
                open_questions=open_questions,
                summary=f"Resolved 0 entities out of {len(request.entity_references)} entity references and left {len(open_questions)} open questions"
            )

        # Only offer searches that fit the type of each entity
        available_searches: list[GraphQueryCall] = []

        for entity_id, match in resolved_entity_details.items():
            labels = match["labels"]

            #Find path to critical assets given the entity is not a critical asset
            if "CriticalAsset" not in labels:
                available_searches.append(GraphQueryCall(operation=GraphOperation.FIND_PATHS, entity_id=entity_id))

            # Get permissions only when the entity is a Role or Service Account
            if any(label in labels for label in ("Role", "ServiceAccount")):
                available_searches.append(GraphQueryCall(operation=GraphOperation.GET_PERMISSIONS, entity_id=entity_id))

            # Get Assest permission only for critical assets
            if "CriticalAsset" in labels:
                available_searches.append(GraphQueryCall(operation=GraphOperation.GET_ASSET_PERMISSIONS, entity_id=entity_id))

            # Get Vulnerabilities only when the entity is a Server or an Application
            if any(label in labels for label in ("Server", "Application")):
                available_searches.append(GraphQueryCall(operation=GraphOperation.GET_VULNERABILITIES, entity_id=entity_id))

            # Perform neighbourhood irrespective of the entity type
            available_searches.append(GraphQueryCall(operation=GraphOperation.EXPAND_NEIGHBORHOOD, entity_id=entity_id))

        # A search already completed before will return the same facts again, so ignore those searches
        available_searches = [
            call for call in available_searches
            if (call.operation, call.entity_id) not in (completed_searches or set())
        ]

        #If no available searches
        if not available_searches:
            return GraphInvestigationResult(
                evidence=evidence,
                discovered_entity_ids=discovered_entity_ids,
                unresolved_entity_references=unresolved_references,
                open_questions=open_questions,
                summary="No new graph searches were available for the requested entities"
            )
        
        plan_input = {
            "objective": request.objective,
            "resolved_entities": [
                {
                    "id": entity_id,
                    "labels": match["labels"],
                    "name": match["properties"].get("name"),
                }
                for entity_id, match in resolved_entity_details.items()
            ],
            "available_searches": [
                call.model_dump(mode="json") for call in available_searches
            ],
        }
        messages = [
            SystemMessage(content=GRAPH_QUERY_SYSTEM_PROMPT),
            HumanMessage(content=json.dumps(plan_input, indent=2)),
        ]

        allowed_call_keys = { (call.operation, call.entity_id) for call in available_searches}

        # Give LLM an extra chance if it chooses a call outisde the allowed keys
        for attempt in range(2):
            plan = self._plan_model.invoke(messages)

            # Track invalid calls if any
            invalid_calls = [
                call.model_dump(mode="json")
                for call in plan.calls
                if (call.operation, call.entity_id) not in allowed_call_keys
            ]

            # There must be atleast 1-3 valid calls per plan 
            if 1<= len(plan.calls) <= 3 and not invalid_calls:
                break

            if attempt == 1: #Attempt Limit exhausted
                raise ValueError("Graph query planner did not select one to three available searches.")
            
            messages.append(
                HumanMessage(
                    content=(
                        "Correction: select one to three operation/entity_id pairs "
                        "exactly from available_searches. Invalid choices: "
                        + json.dumps(invalid_calls)
                    )
                )
            )

        selected_calls = []
        seen_calls = set()

        for call in plan.calls:
            call_key = (call.operation, call.entity_id)

            if call_key not in seen_calls:
                selected_calls.append(call)
                seen_calls.add(call_key)

        # To avoid discovered path from appearing twice
        seen_path_ids = set()

        #Tells us whether "no path found" is a real result or simply unsearched.
        searched_for_paths = False

        for call in selected_calls:
            entity_id = call.entity_id

            if call.operation == GraphOperation.FIND_PATHS:
                searched_for_paths = True
                paths = self._query_client.find_paths_to_critical_assets(entity_id)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"critical-paths-{entity_id}",
                        source_operation=call.operation,
                        content={"entity_id": entity_id, "paths": paths},
                    )
                )
                for path in paths:
                    _collect_node_ids(path.get("nodes", []), discovered_entity_ids)
                    candidate_path = _to_candidate_path(entity_id, path)
                    if candidate_path.path_id not in seen_path_ids:
                        candidate_paths.append(candidate_path)
                        seen_path_ids.add(candidate_path.path_id)

            elif call.operation == GraphOperation.EXPAND_NEIGHBORHOOD:
                neighborhood = self._query_client.expand_neighborhood(entity_id, max_hops=2)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"neighborhood-{entity_id}",
                        source_operation=call.operation,
                        content={"entity_id": entity_id, "paths": neighborhood},
                    )
                )
                for path in neighborhood:
                    _collect_node_ids(path.get("nodes", []), discovered_entity_ids)

            elif call.operation == GraphOperation.GET_PERMISSIONS:
                permissions = self._query_client.get_permissions(entity_id)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"permissions-for-{entity_id}",
                        source_operation=call.operation,
                        content={"principal_id": entity_id, "permissions": permissions},
                    )
                )
                for permission in permissions:
                    asset_id = permission["asset_id"]
                    if asset_id not in discovered_entity_ids:
                        discovered_entity_ids.append(asset_id)

            elif call.operation == GraphOperation.GET_ASSET_PERMISSIONS:
                permissions = self._query_client.get_asset_permissions(entity_id)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"permissions-on-{entity_id}",
                        source_operation=call.operation,
                        content={"asset_id": entity_id, "permissions": permissions},
                    )
                )
                for permission in permissions:
                    principal_id = permission["principal_id"]
                    if principal_id not in discovered_entity_ids:
                        discovered_entity_ids.append(principal_id)

            elif call.operation == GraphOperation.GET_VULNERABILITIES:
                vulnerabilities = self._query_client.get_vulnerabilities(entity_id)
                evidence.append(
                    EvidenceRecord(
                        evidence_id=f"vulnerabilities-{entity_id}",
                        source_operation=call.operation,
                        content={"asset_id": entity_id, "vulnerabilities": vulnerabilities},
                    )
                )
                for vulnerability in vulnerabilities:
                    vulnerability_id = vulnerability["vulnerability_id"]
                    if vulnerability_id not in discovered_entity_ids:
                        discovered_entity_ids.append(vulnerability_id)

        # Only report a missing critical path if that search actually ran.
        if searched_for_paths and not candidate_paths:
            open_questions.append(
                "No path to a critical asset was found within the current "
                "bounded search."
            )

        question_label = "question" if len(open_questions) == 1 else "questions"

        return GraphInvestigationResult(
            evidence=evidence,
            candidate_paths=candidate_paths,
            discovered_entity_ids=discovered_entity_ids,
            unresolved_entity_references=unresolved_references,
            open_questions=open_questions,
            summary=(
                f"Resolved {len(resolved_entity_details)} entities, ran "
                f"{len(selected_calls)} searches, found "
                f"{len(candidate_paths)} candidate paths, and left "
                f"{len(open_questions)} open {question_label}."
            ),
        )    


def _to_candidate_path(
    source_entity_id: str,
    path: dict[str, Any],
) -> CandidatePath:
    """Create a CandidatePath from one Neo4j path result."""
    node_ids = [node["id"] for node in path["nodes"]]
    relationship_ids = [edge["id"] for edge in path["relationships"]]
    path_signature = "-".join(relationship_ids)
    return CandidatePath(
        path_id=f"{source_entity_id}:{path_signature}",
        node_ids=node_ids,
        relationship_ids=relationship_ids,
        critical_asset_id=path["critical_asset_id"],
    )


def _collect_node_ids(
    nodes: list[dict[str, Any]],
    discovered_entity_ids: list[str],
) -> None:
    for node in nodes:
        entity_id = node["id"]
        if entity_id not in discovered_entity_ids:
            discovered_entity_ids.append(entity_id)

            




        


