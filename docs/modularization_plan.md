# Modularization Plan — "Plug In Your Own Assistant"

**Status:** Deferred — revisit after May 7 presentation and May 10 paper submission.

## Motivation

Makes the claim defensible: *"Define your roles and tool permissions in `securellm.yaml`,
register your tools with `register_tool()`, and the full 5-layer security pipeline wraps
them automatically."*

Currently roles and tool permissions are hardcoded in `constants.py`, tools are hardcoded
in the orchestrator, and the model name is hardcoded as a string literal. A new customer
cannot adapt the pipeline without editing source files.

---

## Scope (what changes)

| File | Change |
|------|--------|
| `securellm.yaml` | New — roles, tool permissions, model config |
| `constants.py` | Reads from YAML instead of hardcoded dicts |
| `pipeline/registry.py` | New (~30 lines) — `register_tool()` + tool store |
| `pipeline/llm_client.py` | New (~20 lines) — provider abstraction, Anthropic only |
| `pipeline/orchestrator.py` | Reads tools from registry, model name from config |
| Everything else | No change — security layers untouched |

**Estimated effort:** ~3 hours. Low regression risk.

---

## securellm.yaml

```yaml
llm:
  provider: anthropic          # only supported value for now
  model: claude-haiku-4-5-20251001
  max_tokens: 1024

roles:
  guest: []
  user:  [file_read, search]
  admin: [file_read, file_write, bash, search, external_api]

pipeline:
  input_scanner: true
  policy_engine: true
  tool_sandbox:  true
  output_guard:  true
```

---

## pipeline/registry.py

```python
_TOOL_REGISTRY = {}   # name -> {executor, schema}

def register_tool(name, description, parameters, executor):
    _TOOL_REGISTRY[name] = {
        "executor": executor,
        "schema": {
            "name": name,
            "description": description,
            "input_schema": {"type": "object", "properties": parameters,
                             "required": list(parameters.keys())},
        },
    }

def get_executor(name):
    return _TOOL_REGISTRY[name]["executor"]

def get_claude_tools():
    return [v["schema"] for v in _TOOL_REGISTRY.values()]
```

---

## pipeline/llm_client.py

Provider abstraction — Anthropic only for now, structured for future extension.

```python
def create_client(provider: str, model: str):
    if provider == "anthropic":
        import anthropic
        return anthropic.Anthropic(), model
    raise NotImplementedError(
        f"Provider '{provider}' is not yet supported. "
        "Contributions welcome — add a branch here and normalize the response format."
    )
```

---

## Customer integration example

What a new customer writes to bring their own tools:

```python
# my_tools.py
from pipeline.registry import register_tool

def query_salesforce(object_type: str, filters: str) -> str:
    return salesforce_client.query(object_type, filters)

register_tool(
    name="salesforce_query",
    description="Query Salesforce CRM records.",
    parameters={
        "object_type": {"type": "string", "description": "e.g. Account, Contact"},
        "filters":     {"type": "string", "description": "SOQL WHERE clause"},
    },
    executor=query_salesforce,
)
```

Then in `securellm.yaml`, add `salesforce_query` to whichever roles should have access.
Policy engine and tool sandbox wrap it automatically — no changes to security layers.

---

## What to tell reviewers / in the paper

> "SecureLLM is designed for integration: roles and tool permissions are defined in a YAML
> config, and the tool registry accepts custom tool functions. A team can adapt the pipeline
> to their own assistant by editing the config and registering their tools — no changes to
> the security layers required. Provider abstraction is included for future LLM backend
> flexibility; Anthropic Claude is the supported provider in this release."
