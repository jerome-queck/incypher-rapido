# Framework decision: a bounded readiness workbench

Decision date: 14 September 2026.

Use Python's standard-library `asyncio` for the implemented workbench, with one
small deterministic dispatcher, a fixed pool of workers, and SQLite for local
verified-result reuse. Do not add a model supervisor to choose among three pure
operations. Do not describe simulated I/O timings as evidence about challenge
solving, model latency, or competition performance.

## Considered options

| Option | Documented capability | Fit for this delivered scope |
| --- | --- | --- |
| asyncio | Task groups, cancellation, timeouts, concurrency | Selected: no dependency or graph state needed |
| LangGraph | Graph state, parallel nodes, stateful workflows | More machinery than this small fixture runner needs |
| Pydantic AI | Typed model outputs and agent/tool interface | Relevant to benign model-assisted analysis, but no model layer is shipped here |

The choice is for this **non-offensive readiness tool**, not a validated claim
about the best autonomous CTF-solving architecture. Neither competing framework
was installed or benchmarked. No live model was called.

Graph scheduling and model/tool latency are separate questions. LangGraph's
documented super-step semantics explain its graph behavior but do not establish
that every graph is slow. Pydantic AI's typed outputs may reduce integration work,
but that does not prove higher solve rates. A meaningful performance claim would
require an agreed workload, identical model/provider settings, repeated trials,
cost accounting, failure rates, and end-to-end measurements.

This implementation deliberately avoids multi-agent voting, generic executor
plugins, dynamic tool discovery, and a second network stack in workers. The only
runtime dependency is the Python standard library. Offline tasks never receive
Board credentials or live challenge content.

## Primary sources consulted

- Python tasks and cancellation:
  https://docs.python.org/3/library/asyncio-task.html
- LangGraph Graph API and super-steps:
  https://docs.langchain.com/oss/python/langgraph/graph-api
- Pydantic AI agents:
  https://pydantic.dev/docs/ai/core-concepts/agent/
- Pydantic AI durable execution:
  https://pydantic.dev/docs/ai/capabilities/durable_execution/overview/
