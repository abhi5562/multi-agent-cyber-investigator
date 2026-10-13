from src.agents import CoordinatorAgent, RiskAnalyst, GraphInvestigator
from src.schema import (
    AgentName,
    EvidenceRecord,
    InvestigationEvent,
    InvestigationState,
    InvestigationStatus,
    NextAction,
    RiskAssessment,
)

from langgraph.graph import END, START, StateGraph
import json

def build_investigation_graph(coordinator: CoordinatorAgent, risk_analyst: RiskAnalyst, graph_investigator: GraphInvestigator):

    # Creates final summary when the coordinator ends the investigation
    def finish(state: InvestigationState, status: InvestigationStatus):
        #Confirmed paths
        confirmed = [
            finding for finding in state["risk_findings"]
            if finding.assessment == RiskAssessment.CONFIRMED
        ]

        path_by_id = {path.path_id: path for path in state["candidate_paths"]}
        lines = [f"Investigation status: {status.value}."]

        #Explain each confirmed path finding
        for finding in confirmed:
            path = path_by_id.get(finding.path_id)
            if path:
                lines.append(
                    f"Potential exposure path: {' -> '.join(path.node_ids)}. "
                    f"{finding.explanation}"
                )

        # If we have no confirmed findings and no open questions it means no exposure path was confirmed
        if not confirmed and not state["open_questions"]:
            lines.append("No supported critical-asset exposure path was confirmed.")

        return {
            "status": status,
            "next_action": None,
            "agent_request": None,
            "final_summary": "\n".join(lines),
        }

    # handles what coordinator chooses next or whether it closes the investigation
    def coordinate(state: InvestigationState):
        # Repeating the same work cannot answer the remaining questions.
        if state["no_progress"]:
            return finish(state, InvestigationStatus.INSUFFICIENT_EVIDENCE)

        # If the search found no paths, there is nothing for the Risk Analyst to assess.
        empty_path_search = any(
            record.source_operation == "find_paths_to_critical_assets"
            and not record.content.get("paths")
            for record in state["evidence"]
        )
        if (
            state["history"]
            and state["history"][-1].agent == AgentName.GRAPH_INVESTIGATOR
            and not state["candidate_paths"]
            and empty_path_search
        ):
            return {
                **finish(state, InvestigationStatus.COMPLETED),
                "open_questions": [],
                "final_summary": (
                    "Investigation status: completed.\n"
                    "No critical-asset exposure path was found within the "
                    "bounded graph search."
                ),
            }

        decision = coordinator.decide(state)

        #If the coordinator decides to finalize the investigation
        if decision.next_action == NextAction.FINALIZE:
            status = InvestigationStatus.COMPLETED if state["risk_evidence_sufficient"] is True else InvestigationStatus.INSUFFICIENT_EVIDENCE

            return {
                **finish(state, status),
                "investigation_goal": decision.investigation_goal
            }

        # Another call to risk_analyst will not help if we have no new graph facts
        if decision.next_action == NextAction.ANALYZE_RISK and state["risk_evidence_sufficient"] is False and state["history"] and state["history"][-1].agent == AgentName.RISK_ANALYST:
            return {
                **finish(state, InvestigationStatus.INSUFFICIENT_EVIDENCE),
                "investigation_goal": decision.investigation_goal,
            }

        # Allow a final answer after the last round, but prevent another round.
        if state["round_count"] >= state["max_rounds"]:
            return {
                **finish(state, InvestigationStatus.LIMIT_REACHED),
                "investigation_goal": decision.investigation_goal,
            }

        return {
            "investigation_goal": decision.investigation_goal,
            "next_action": decision.next_action,
            "agent_request": decision.agent_request,
        }

    # Replace the old risk judgments with an assessment of the current paths.
    def analyze_risk(state: InvestigationState):
        request = state["agent_request"]

        if request is None:
            raise ValueError("Risk analysis requires an agent request")

        result = risk_analyst.analyze_risk(state, request)
        round_number = state["round_count"] + 1

        updates = {
            "risk_findings": result.findings,
            "risk_evidence_sufficient": result.evidence_sufficient,
            "open_questions": result.open_questions,
            "round_count": round_number,
            "history": state["history"] + [
                InvestigationEvent(
                    round_number=round_number,
                    agent=AgentName.RISK_ANALYST,
                    outcome=result.summary,
                    evidence_ids=[record.evidence_id for record in state["evidence"]],
                )
            ],
            # An unchanged assessment cannot move the investigation forward.
            "no_progress": (
                result.findings == state["risk_findings"]
                and result.evidence_sufficient == state["risk_evidence_sufficient"]
                and result.open_questions == state["open_questions"]
            ),
        }

        return updates

    # Save what the graph found and check whether it adds anything useful.
    def investigate_graph(state: InvestigationState):
        request = state["agent_request"]
        if request is None:
            raise ValueError("Graph investigation requires an agent request.")

        # Compute all the computed searches so that the same search is not repeated again
        completed_searches = {
            (
                record.source_operation,
                record.content.get("entity_id")
                or record.content.get("principal_id")
                or record.content.get("asset_id"),
            )
            for record in state["evidence"]
            if record.source_operation != "resolve_entity"
        }

        result = graph_investigator.investigate(request, completed_searches)

        #Function to create evidence_key for an evidence
        def evidence_key(record: EvidenceRecord) -> tuple[str, str | None]:
            if record.source_operation == "resolve_entity":
                return (record.source_operation, record.content.get("reference"))
            return (record.source_operation, record.evidence_id)

        # Index existing evidence by its key, then overwrite entries with fresh results.
        evidence_by_id = {evidence_key(record): record for record in state["evidence"]}
        for record in result.evidence:
            evidence_by_id[evidence_key(record)] = record

        # Index existing paths by path ID, then add or update paths returned by this search.
        paths_by_id = {path.path_id: path for path in state["candidate_paths"]}
        for path in result.candidate_paths:
            paths_by_id[path.path_id] = path

        evidence = list(evidence_by_id.values())
        paths = list(paths_by_id.values())

        # Row order may change even when a graph search returns the same facts.
        def evidence_content(record: EvidenceRecord) -> str:
            content = record.content.copy()
            for field in ("matches", "paths", "permissions", "vulnerabilities"):
                if field in content:
                    content[field] = sorted(
                        json.dumps(row, sort_keys=True) for row in content[field]
                    )
            return json.dumps(content, sort_keys=True)

        old_facts = {
            evidence_key(record): evidence_content(record)
            for record in state["evidence"]
        }

        current_facts = {
            evidence_key(record): evidence_content(record)
            for record in evidence
        }

        old_paths = {path.path_id: path for path in state["candidate_paths"]}

        # Whether a new search ran in the latest investigation
        ran_new_search = any(record.source_operation != "resolve_entity" for record in result.evidence)

        # Computes whether facts or changed or not
        facts_changed = ran_new_search and (old_facts != current_facts or old_paths != paths_by_id)

        new_questions = [
            question for question in result.open_questions
            if question not in state["open_questions"]
        ]

        changed = facts_changed or bool(new_questions) #Used to track progress
        round_number = state["round_count"] + 1

        history = state["history"] + [
            InvestigationEvent(
                round_number=round_number,
                agent=AgentName.GRAPH_INVESTIGATOR,
                outcome=result.summary,
                evidence_ids=[record.evidence_id for record in result.evidence],
            )
        ]

        updates = {
            "evidence": evidence,
            "candidate_paths": paths,
            "open_questions": (
                result.open_questions if facts_changed
                else state["open_questions"] + new_questions
            ),
            "round_count": round_number,
            "history": history,
            "no_progress": not changed,
        }

        # Earlier risk judgments need another review when the graph facts change. So, reset risk_findings and risk_evidence_sufficient values for the next round of investigation
        if facts_changed:
            updates.update(risk_findings=[], risk_evidence_sufficient=None)

        return updates
    
    def route(state: InvestigationState):
        if state["status"] != InvestigationStatus.IN_PROGRESS:
            return END

        return {
            NextAction.INVESTIGATE_GRAPH: "graph_investigator",
            NextAction.ANALYZE_RISK: "risk_analyst"
        }[state["next_action"]]

    # Both Specialist agents return to the Coordinator for the next decision.
    graph = StateGraph(InvestigationState)
    graph.add_node("coordinator", coordinate)
    graph.add_node("graph_investigator", investigate_graph)
    graph.add_node("risk_analyst", analyze_risk)
    graph.add_edge(START, "coordinator")
    graph.add_conditional_edges("coordinator", route)
    graph.add_edge("graph_investigator", "coordinator")
    graph.add_edge("risk_analyst", "coordinator")
    return graph.compile()
