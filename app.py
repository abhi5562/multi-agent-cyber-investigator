"""Streamlit interface for graph-based security investigations.

Run with: streamlit run app.py
"""

from dotenv import load_dotenv
import streamlit as st

from src.agents import CoordinatorAgent, GraphInvestigator, RiskAnalyst
from src.graph import build_investigation_graph
from src.schema import InvestigationStatus
from src.tools.graph_queries import GraphQueries
from src.tools.neo4j_client import Neo4jClient


load_dotenv()


def create_initial_state(question: str):
    return {
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


def investigate(question: str):
    """Run one question through the investigation workflow."""
    with Neo4jClient() as client:
        client.check_connection()
        workflow = build_investigation_graph(
            CoordinatorAgent(),
            RiskAnalyst(),
            GraphInvestigator(GraphQueries(client)),
        )
        return workflow.invoke(create_initial_state(question))


def show_result(result):
    status = result["status"]
    st.subheader("Investigation status")
    if status == InvestigationStatus.COMPLETED:
        st.success("Completed")
    elif status == InvestigationStatus.INSUFFICIENT_EVIDENCE:
        st.warning("Insufficient evidence")
    else:
        st.error("Limit reached")

    paths_by_id = {path.path_id: path for path in result["candidate_paths"]}
    confirmed_findings = [
        finding
        for finding in result["risk_findings"]
        if finding.assessment.value == "confirmed"
    ]

    st.subheader("Potential exposure paths")
    if confirmed_findings:
        for finding in confirmed_findings:
            path = paths_by_id.get(finding.path_id)
            if path:
                st.write(f"{' → '.join(path.node_ids)}")
                st.caption(f"Critical asset: {path.critical_asset_id}")
    else:
        st.info("No potential exposure path was confirmed.")

    st.subheader("Explanation")
    st.write(result["final_summary"])

    if result["risk_findings"]:
        st.subheader("Risk findings")
        for finding in result["risk_findings"]:
            st.markdown(f"**{finding.assessment.value.replace('_', ' ').title()}**")
            st.write(finding.explanation)
            for question in finding.missing_evidence:
                st.caption(f"Missing evidence: {question}")

    if result["candidate_paths"]:
        with st.expander("All candidate paths"):
            for path in result["candidate_paths"]:
                st.write(f"{' → '.join(path.node_ids)}")
                st.caption(f"Critical asset: {path.critical_asset_id}")

    if result["open_questions"]:
        with st.expander("Open questions"):
            for question in result["open_questions"]:
                st.write(f"- {question}")

    with st.expander("Investigation rounds"):
        for event in result["history"]:
            st.write(f"Round {event.round_number} — {event.agent.value}: {event.outcome}")
            st.caption(f"Evidence: {', '.join(event.evidence_ids)}")


st.set_page_config(page_title="Enterprise Investigation", page_icon="🔎")
st.title("Enterprise Investigation")
st.caption("Ask whether an entity could expose a critical database in the Neo4j graph.")

question = st.chat_input(
    "For example: If Employee-17 is compromised, which critical databases could be exposed?"
)
if question:
    with st.chat_message("user"):
        st.write(question)

    with st.chat_message("assistant"):
        with st.spinner("Investigating the graph..."):
            try:
                result = investigate(question)
            except Exception as error:
                st.error(f"Investigation failed: {error}")
            else:
                show_result(result)
