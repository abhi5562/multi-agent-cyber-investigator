"""Run one question against the configured Neo4j investigation graph."""

from dotenv import load_dotenv

from src.agents import CoordinatorAgent, GraphInvestigator, RiskAnalyst
from src.graph import build_investigation_graph
from src.schema import InvestigationStatus
from src.tools.graph_queries import GraphQueries
from src.tools.neo4j_client import Neo4jClient


load_dotenv()

# Change this question to try another entity or investigation.
question = "Can Employee-17 access Customer-DB through Payroll-App?"

initial_state = {
    "user_query": question,
    "investigation_goal": question,
    "evidence": [],
    "candidate_paths": [],
    "risk_findings": [],
    "risk_evidence_sufficient": None,
    "open_questions": [],
    "next_action": None,
    "agent_request": None,
    "history": [],
    "round_count": 0,
    "max_rounds": 5,
    "no_progress": False,
    "status": InvestigationStatus.IN_PROGRESS,
    "final_summary": None,
}

with Neo4jClient() as client:
    client.check_connection()
    workflow = build_investigation_graph(
        CoordinatorAgent(),
        RiskAnalyst(),
        GraphInvestigator(GraphQueries(client)),
    )
    result = workflow.invoke(initial_state)

print("QUESTION:", question)
print("STATUS:", result["status"].value)
print("AGENT SEQUENCE:", [event.agent.value for event in result["history"]])

print("\nINVESTIGATION ROUNDS:")
for event in result["history"]:
    print(f"Round {event.round_number} ({event.agent.value}): {event.outcome}")
    print("  Evidence IDs:", event.evidence_ids)

print("\nCANDIDATE PATHS:")
for path in result["candidate_paths"]:
    print(f"{' -> '.join(path.node_ids)} (critical asset: {path.critical_asset_id})")

print("\nRISK FINDINGS:")
for finding in result["risk_findings"]:
    print(finding.model_dump_json(indent=2))

if result["open_questions"]:
    print("\nOPEN QUESTIONS:")
    for item in result["open_questions"]:
        print("-", item)

print("\nFINAL SUMMARY:")
print(result["final_summary"])
