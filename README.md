# Multi-Agent Cybersecurity Investigation & Attack-Path Analysis

A graph-based cybersecurity investigation project that uses AI agents to explore how enterprise identities and systems may expose critical databases. It combines Neo4j graph retrieval with a LangGraph workflow to turn natural-language security questions into evidence-backed path assessments.

The project supports questions such as:

- “If Employee-17 is compromised, which critical databases could be exposed?”
- “Can Employee-17 access Customer-DB through Payroll-App?”

These are example questions used by the entry points; investigations use the entities and relationships in the connected Neo4j database.

## How it works

Three agents collaborate through a shared investigation state:

1. **Coordinator:** interprets the investigation goal and decides whether to gather graph evidence, assess candidate paths, or finalize the result.
2. **Graph Investigator:** resolves entity names or IDs and selects predefined, read-only searches for paths to critical assets, nearby relationships, permissions, and vulnerabilities. Python executes the Cypher queries and records the evidence.
3. **Risk Analyst:** evaluates candidate paths using retrieved relationship evidence and classifies each as confirmed, rejected, or needing more evidence. It distinguishes network connectivity from database access permissions.

LangGraph routes work between the agents and maintains evidence, candidate paths, findings, open questions, and investigation history. The Coordinator can request further retrieval when an assessment needs additional facts. The workflow tracks progress and applies stopping conditions before producing a final status and summary.

## Enterprise graph

Neo4j represents enterprise entities such as users, devices, roles, applications, servers, service accounts, databases, and vulnerabilities. Assets marked with the `CriticalAsset` label are the targets of exposure-path searches.

Relationships capture identity membership, system usage, application hosting, service identities, permissions, network connectivity, dependencies, and vulnerabilities. The investigation uses these connections and their properties to explain potential routes from an entity to a critical asset.

## Interfaces and results

- **Streamlit interface (`app.py`):** accepts a security question and displays the investigation status, confirmed potential exposure paths, explanations, risk findings, candidate paths, open questions, and investigation rounds.
- **Command-line example (`main.py`):** runs a question defined in the file and prints the agent sequence, retrieved candidate paths, findings, and final summary.

Findings link assessments to graph paths, preserving the distinction between a potential exposure and an actual compromise.

## Project structure

```text
app.py                       Streamlit interface
main.py                      Command-line example
requirements.txt             Python dependencies
src/
├── agents/
│   ├── coordinator.py        Investigation routing
│   ├── graph_investigator.py Search planning and evidence retrieval
│   └── risk_analyst.py       Path assessment
├── graph.py                  LangGraph workflow and stopping conditions
├── prompts.py                Agent instructions
├── schema.py                 Shared state and structured result models
└── tools/
    ├── graph_queries.py      Read-only Cypher operations
    └── neo4j_client.py       Neo4j connection and query execution
```

## Technology

Python · LangGraph · LangChain OpenAI · Neo4j · Pydantic · Streamlit · python-dotenv
