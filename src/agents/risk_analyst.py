from langchain_openai import ChatOpenAI
from src.schema import PathAssessment, InvestigationState, AgentRequest, RiskAnalysisResult, AgentName, RiskFinding, RiskAssessment
from typing import Any
from langchain_core.messages import HumanMessage, SystemMessage
from src.prompts import RISK_ANALYST_SYSTEM_PROMPT
import json

class RiskAnalyst:
    def __init__(self):
        self._chat_model = ChatOpenAI(model='gpt-5.6')
        self._path_assessment_model = self._chat_model.with_structured_output(PathAssessment)

    def analyze_risk(self, state: InvestigationState, request: AgentRequest) -> RiskAnalysisResult:
        #Checking whether target agent is RISK_ANALYST
        if request.target_agent != AgentName.RISK_ANALYST:
            raise ValueError("Risk analyst can only process request where the target agent is RISK ANALYST")

        #We cannot analyze anything if we have no paths to critical db
        if not state['candidate_paths']:
            return RiskAnalysisResult(
                findings=[],
                evidence_sufficient=False,
                open_questions=["Are there any graph paths from the entity being investigated to a critical database?"],
                summary="No candidate paths to a critical database were available."
            )

        # Map each relationship ID to its Neo4j Relationship details 
        relationships_by_id: dict[str, dict[str, Any]] = {}
        for evidence in state["evidence"]:
            for path in evidence.content.get("paths", []):
                for relationship in path.get("relationships", []):
                    relationship_id = relationship.get("id")
                    if relationship_id:
                        relationships_by_id[relationship_id] = relationship

        findings: list[RiskFinding] = []

        for candidate_path in state["candidate_paths"]:
            path_relationship_details = [] # Store relationship details for the current path in traversal order.
            missing_relationship_ids = [] #Track relationship id's whos info is missing from the evidence
            for relationship_id in candidate_path.relationship_ids:
                relation_details = relationships_by_id.get(relationship_id)

                if relation_details is None:
                    missing_relationship_ids.append(relationship_id)
                
                path_relationship_details.append(relation_details)

            # Handle relationships whose details are not present deterministically
            if missing_relationship_ids:
                first_missing_id = missing_relationship_ids[0]
                missing_index = candidate_path.relationship_ids.index(first_missing_id)
                source_id = candidate_path.node_ids[missing_index]
                target_id = candidate_path.node_ids[missing_index+1]
                question = (f"What relationship connectes {source_id} to {target_id} for relationship with id {first_missing_id}")
                findings.append(
                    RiskFinding(
                        path_id=candidate_path.path_id,
                        assessment=RiskAssessment.NEEDS_MORE_EVIDENCE, #because we have missing info on some relationships
                        explanation="The path cannot be assessed because some relationship details are missing from the retrieved evidence.",
                        missing_evidence=[question]
                    )
                )
                continue

            # Handle paths where the ending relationship is "CONNECTED_TO" deterministically (Which alone does not prove that critical asset is accessible)
            if path_relationship_details[-1]["type"] == "CONNECTED_TO":
                source_id = candidate_path.node_ids[-2]
                target_id = candidate_path.critical_asset_id
                question = f"Does {source_id} have permission or credentials to access {target_id}"
                findings.append(
                    RiskFinding(
                        path_id=candidate_path.path_id,
                        assessment=RiskAssessment.NEEDS_MORE_EVIDENCE,
                        explanation=f"{source_id} can reach {target_id} over network, but connectivity alone does not prove databasea access",
                        missing_evidence=[question]
                    )
                )
                continue

            prompt_payload = {
                "investigation_goal": state["investigation_goal"],
                "agent_objective": request.objective,
                "candidate_path": candidate_path.model_dump(mode="json"),
                "relationships": path_relationship_details,
            }

            llm_assessment: PathAssessment = self._path_assessment_model.invoke(
                [
                    SystemMessage(content=RISK_ANALYST_SYSTEM_PROMPT),
                    HumanMessage(
                        content="Path to assess\n" + json.dumps(prompt_payload, indent=2)
                    )
                ]
            )

            #HANDLE LLM ASSESSMENT INACCURACIES OR MISTAKES

            #Manually add missing_evidence if llm missed adding missing_evidence for a path it classified as "needs more evidence"
            if llm_assessment.assessment == RiskAssessment.NEEDS_MORE_EVIDENCE and not llm_assessment.missing_evidence:
                llm_assessment.missing_evidence.append(
                    f"What additional permission or credentials details/evidence connects {candidate_path.node_ids[-2]} to {candidate_path.critical_asset_id}"
                )

            #Manually make the missing_evidence empty as Confirmed or Rejected paths must not carry additional questions
            if llm_assessment.assessment in {RiskAssessment.CONFIRMED, RiskAssessment.REJECTED}:
                llm_assessment.missing_evidence = []

            findings.append(
                RiskFinding(
                    path_id=candidate_path.path_id,
                    assessment=llm_assessment.assessment,
                    explanation=llm_assessment.explanation,
                    missing_evidence=llm_assessment.missing_evidence
                )
            )

        # Map every path id with its critical db id
        path_id_to_critical_asset = {}
        for path in state["candidate_paths"]:
            path_id_to_critical_asset[path.path_id] = path.critical_asset_id

        # Set of Critical assests that have alteast one confirmed exposure
        confirmed_critical_ids = set()
        for finding in findings:
            if finding.assessment == RiskAssessment.CONFIRMED:
                confirmed_critical_ids.add(path_id_to_critical_asset[finding.path_id])

        # Questions which prevent the investigation from answering the mail goal (only consider paths which need more evidence)
        open_questions = []

        for finding in findings:
            critical_asset_id = path_id_to_critical_asset[finding.path_id]

            if critical_asset_id in confirmed_critical_ids:
                continue

            for question in finding.missing_evidence:
                open_questions.append(question)

        # Summary count
        confirmed_count = sum(finding.assessment == RiskAssessment.CONFIRMED for finding in findings)
        rejected_count = sum(finding.assessment == RiskAssessment.REJECTED for finding in findings)
        unresolved_count = sum(finding.assessment == RiskAssessment.NEEDS_MORE_EVIDENCE for finding in findings)

        # Evidence is sufficient where there are no open questions
        evidence_sufficient = not open_questions

        summary = (
            f"Assessed {len(findings)} paths to critical databases: "
            f"{confirmed_count} confirmed, {rejected_count} rejected, and "
            f"{unresolved_count} needing more evidence."
        )

        return RiskAnalysisResult(
            findings=findings,
            evidence_sufficient=evidence_sufficient,
            open_questions=open_questions,
            summary=summary
        )



        


            




            




        



        

        

        