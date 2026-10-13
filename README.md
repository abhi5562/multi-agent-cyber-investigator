# Multi-Agent Cybersecurity Investigation & Attack-Path Analysis

This project investigates how an entity in a synthetic enterprise environment may be connected to critical assets. It combines relationship-aware retrieval from Neo4j with a LangGraph workflow that gathers graph evidence, assesses candidate paths, and decides whether another investigation step is needed.

The goal is to make exposure paths easier to understand: **which systems and identities connect a user to a critical asset, what graph evidence supports that path, and where the evidence is incomplete.** The project is intended for defensive analysis of synthetic data. It does not execute exploits or access real enterprise infrastructure.

## How it works

- **Coordinator:** reviews the investigation state and chooses whether to retrieve graph evidence, assess risk, or stop.
- **Graph Investigator:** resolves entity names and chooses from predefined, read-only graph operations. It does not write arbitrary Cypher. Searches include path discovery, neighborhood expansion, permission lookup, and vulnerability lookup.
- **Risk Analyst:** assesses candidate paths using the retrieved relationships. It can identify missing evidence; network connectivity alone is not treated as proof of database authorization.
- **LangGraph:** carries shared state between agents, routes their work, and supports repeated investigation with stop conditions.
- **Neo4j:** is the source of truth for entities, relationships, permissions, dependencies, vulnerabilities, and critical asset labels. Python/Cypher performs the actual bounded queries.

The coordinator can send work back for more evidence or finish with an insufficient-evidence or iteration-limit status. Investigations have a configurable maximum of five rounds in the current entry points.

## Graph model

The synthetic enterprise graph uses labeled nodes such as:

| Node labels                     | Example properties                     |
| ------------------------------- | -------------------------------------- |
| `User`, `Device`, `Role`  | name, department, status, network zone |
| `Application`, `Server`     | name, environment, business function   |
| `ServiceAccount`              | name, privilege level, status          |
| `Database`, `CriticalAsset` | name, classification, criticality      |
| `Vulnerability`               | name, severity, status, effect         |

Relationships describe how entities connect, for example `USES`, `MEMBER_OF`, `HAS_PERMISSION_ON`, `RUNS_ON`, `USES_IDENTITY`, `CONNECTED_TO`, `DEPENDS_ON`, and `HAS_VULNERABILITY`. Permission level, network port, and protocol can be stored as relationship properties. `CriticalAsset` is an additional label on assets that should be included in critical-asset path searches.

An illustrative path in the sample graph is:

```text
Employee-17
  -[:MEMBER_OF]-> Finance-User-Role
  -[:HAS_PERMISSION_ON {permission: "USE"}]-> Payroll-App
  -[:RUNS_ON]-> App-Server-01
  -[:USES_IDENTITY]-> ServiceAccount-02
  -[:HAS_PERMISSION_ON {permission: "READ_WRITE"}]-> Customer-DB
```

The graph also records a high-severity unpatched synthetic vulnerability on `App-Server-01` and a network connection from that server to `Customer-DB`. These facts provide context; the system should distinguish direct permission evidence from connectivity or vulnerability evidence.

## Repository layout

```text
.
├── app.py                       # Streamlit interface
├── main.py                      # Command-line example
├── requirements.txt
└── src/
    ├── agents/
    │   ├── coordinator.py       # Routing decisions
    │   ├── graph_investigator.py # Search planning and evidence retrieval
    │   └── risk_analyst.py      # Path assessment
    ├── graph.py                 # LangGraph workflow and stop conditions
    ├── prompts.py               # Agent instructions
    ├── schema.py                # Shared state and structured result models
    └── tools/
        ├── graph_queries.py     # Bounded read-only Cypher operations
        └── neo4j_client.py     # Neo4j connection
```

## Scope and current limits

- The included interface and command-line entry point connect to Neo4j; the repository does not provision a database or load the sample graph automatically.
- Path searches are bounded to four hops and up to 50 results; neighborhood expansion is bounded to two hops. These are retrieval limits, not a guarantee that every possible path has been found.
- Findings depend on graph completeness and the evidence returned by the configured model. An unobserved path should not be interpreted as proof that no path exists.

## Technology

Python · LangGraph · LangChain OpenAI · Neo4j · Pydantic · Streamlit
