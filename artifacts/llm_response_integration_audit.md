# LLM to Response Agent integration audit

## Verified call graph

`MonitoringEngine._ingest_batch()` persists deterministic evidence, evaluates
`DetectionPipeline`, and calls `TriageEngine` to persist a case. This path was
not changed. `InvestigationAgent.investigate()` reads an existing case/evidence,
produces the deterministic `InvestigationResult`, then optionally calls
`IntelligenceService.interpret(result)`. The interpretation is stored on that
result in `investigation_results`.

`ResponseAgent.plan()` reads the persisted result. Its new
`_advisory_intelligence_context()` admits only a COMPLETE interpretation whose
cited IDs are a nonempty subset of deterministic `evidence_ids_used`. It stores
the context on `ResponsePlan.intelligence_context` with
`authority: ADVISORY_ONLY`. Playbook action generation, `PolicyEvaluator`,
approval, adapter selection, verification, and persistence retain authority.

## Provider status

Configured protocol support is Gemini (default: `GEMINI_API_KEY`) or HTTPS
OpenAI-compatible (`AEGIS_LLM_BASE_URL`, `AEGIS_LLM_API_KEY`,
`AEGIS_LLM_MODEL`). The current environment selects `openai-compatible` and
has a base URL and model configured, but both supported credential variables
are absent. `scripts/live_llm_smoke.py` therefore returned `DISABLED` before
making a provider request. Live-provider status is **blocked, not passed**.
The exact operator command is in the Windows walkthrough.

## Test distinction

- Mock/controlled: LLM-to-response tests validate propagation of a completed
  grounded interpretation, omission of fabricated IDs, and no automatic action
  authorization.
- Focused regression command:
  `python -m pytest -q tests/test_intelligence.py tests/test_response_agent.py tests/test_config.py`
  completed with 35 passing tests.
- Provider failure: `IntelligenceService` returns an explicit status and does
  not interrupt deterministic results.
- Live Windows: previous controlled monitoring and LocalLab containment results
  remain separate from LLM provider validation.

## Residual limitation

The current LLM schema intentionally provides interpretation, insights, and
uncertainties rather than executable recommendations. This is a deliberate
security boundary: there is no model-to-shell, model-to-handler, or
model-to-approval path. A COMPLETE interpretation is visible to the response
operator in the persisted plan but cannot alter action selection or policy.
