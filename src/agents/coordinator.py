from langchain_openai import ChatOpenAI
from src.schema import CoordinatorDecision, InvestigationState, NextAction, RiskAssessment, AgentName
from src.prompts import COORDINATOR_SYSTEM_PROMPT
from langchain_core.messages import HumanMessage, SystemMessage
from collections.abc import Sequence
from pydantic import BaseModel
from typing import Any
import json

class CoordinatorAgent:
    def __init__(self):
        self._decision_model = ChatOpenAI(model="gpt-5.6").with_structured_output(CoordinatorDecision)

    def decide(self, state: InvestigationState) -> CoordinatorDecision:
        messages = [
            SystemMessage(content=COORDINATOR_SYSTEM_PROMPT),
            HumanMessage(content=_format_state_for_coordinator(state)),
        ]

        decision = self._decision_model.invoke(messages)

        # The Coordinator cannot finalize the decision without having any risk findings
        if decision.next_action == NextAction.FINALIZE and state["candidate_paths"] and not state["risk_findings"]:
            messages.append(
                HumanMessage(
                    content=(
                        "Correction: candidate paths have been found, but there are "
                        "no risk findings yet. Choose analyze_risk or "
                        "investigate_graph based on the current evidence. Do not "
                        "finalize from graph paths alone."
                    )
                )
            )

            # Try to decide again
            decision = self._decision_model.invoke(messages)

            #If still the same, then raise Error
            if decision.next_action == NextAction.FINALIZE:
                raise ValueError(
                    "Coordinator cannot finalize candidate paths before risk analysis."
                )

        # If atleast one risk analysis of a finding confirmed, move on to the final answer. Do not continue the investigation
        has_confirmed_finding = any(
            f.assessment == RiskAssessment.CONFIRMED for f in state["risk_findings"]
        )

        last_step_was_risk_analyst = (
            state["history"]
            and state["history"][-1].agent == AgentName.RISK_ANALYST
        )

        if (
            decision.next_action != NextAction.FINALIZE
            and state["risk_evidence_sufficient"] is True
            and not state["open_questions"]
            and has_confirmed_finding
            and last_step_was_risk_analyst
        ):
            messages.append(
                HumanMessage(
                    content=(
                        "Correction: the latest Risk Analyst result says the "
                        "evidence is sufficient, a confirmed path answers the "
                        "goal, and there are no blocking open questions. An "
                        "unresolved alternate path is only a caveat. Finalize "
                        "using the existing findings."
                    )
                )
            )

            # Try once more
            decision = self._decision_model.invoke(messages)

            #If still the same problem raise an Error
            if decision.next_action != NextAction.FINALIZE:
                raise ValueError(
                    "Coordinator requested more work after sufficient risk analysis."
                )

        return decision
        

def _format_state_for_coordinator(state: InvestigationState) -> str:
    """Investigation state needed for the routing decision."""
    payload = {
        "user_query": state["user_query"],
        "investigation_goal": state["investigation_goal"],
        "evidence": _dump_models(state["evidence"]),
        "candidate_paths": _dump_models(state["candidate_paths"]),
        "risk_findings": _dump_models(state["risk_findings"]),
        "risk_evidence_sufficient": state["risk_evidence_sufficient"],
        "open_questions": state["open_questions"],
        "history": _dump_models(state["history"]),
        "round_count": state["round_count"],
        "max_rounds": state["max_rounds"],
        "status": state["status"],
        "final_summary": state["final_summary"],
    }
    return "Current investigation state:\n" + json.dumps(
        payload,
        indent=2,
        sort_keys=True,
    )

def _dump_models(records: Sequence[BaseModel]) -> list[dict[str, Any]]:
    return [record.model_dump(mode="json") for record in records]