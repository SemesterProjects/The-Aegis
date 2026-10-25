# LLM investigation interpretation

The LLM layer is optional and disabled by default. It runs only after the
deterministic InvestigationAgent has collected evidence and selected a result.
It cannot collect telemetry, query SQLite, call tools, run shell commands,
modify a host, alter a classification, or trigger remediation.

For local development, copy `.env.example` to `.env` and place the key only in
that ignored file. Aegis loads `.env` when its CLI starts, but explicit process
environment variables take precedence. `.env` is not a production secret
manager: use an OS credential store, a deployment secret manager, restricted
service identity, and rotation policy in deployed environments.

For development, Aegis defaults to Gemini's REST API with
`gemini-3.5-flash-lite`; Google currently lists a limited free tier for that
model. Its free-tier data handling is not appropriate for production-sensitive
telemetry: review the provider's current terms before use. Create an API key in
Google AI Studio, restrict it to the Generative Language API, and set it only
in the current shell:

```powershell
$env:GEMINI_API_KEY = "..."
python -m aegis_core investigate INC-EXAMPLE --data-dir .\aegis-data --llm --json
```

Verify a configured provider without sending real host data:

```powershell
python scripts\live_llm_smoke.py
```

For another approved OpenAI-compatible service, set
`AEGIS_LLM_PROVIDER=openai-compatible` plus `AEGIS_LLM_BASE_URL` (HTTPS only),
`AEGIS_LLM_API_KEY`, and `AEGIS_LLM_MODEL`.

`AEGIS_LLM_TIMEOUT_SECONDS` is optional and defaults to 15 seconds. The
provider must implement the OpenAI-compatible `/chat/completions` endpoint and
support JSON-object responses.

Only a bounded, minimised evidence pack is sent: deterministic summary and
classification, timeline/evidence descriptions, allowed event IDs, and known
uncertainties. The API key is read from the process environment only. Do not
put credentials in CLI arguments, config files, evidence records, or logs.

The returned `llm_interpretation` has an explicit status. `COMPLETE` output is
accepted only when it is bounded JSON and every cited ID is present in the
supplied evidence pack. Invalid, unavailable, or failed model calls are stored
as interpretation status and never fail the deterministic investigation.
