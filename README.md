# ThreatGuard AI — Multi-Platform Threat Intelligence Assistant

A defensive, MongoDB-backed RAG chat application for Windows, Linux, macOS, Android and iOS threat-intelligence queries.

## What is included

- FastAPI backend: `/chat`, `/threats`, `/ingest`, `/sessions/{id}`, `/stats`, `/health`, `/metrics`, `/scan/local`
- MongoDB operational store, vector/chunk store and persistent conversation memory
- Ollama local LLM and embedding integration; optional OpenAI chat provider
- Streamlit chat UI with platform and lifecycle filters
- Docker Compose deployment with persistent MongoDB volume and health checks
- Optional API-key protection, basic per-client rate limiting and Prometheus metrics
- Read-only inventory helper

## Requirements

- Windows 10/11 with Docker Desktop and Docker Compose
- 8 GB RAM is a practical minimum for a small local model; more memory improves performance
- Internet access for the initial Docker image/model downloads
- Ollama model download is optional for starting the stack, but required for genuine local LLM/embedding inference

## Windows quick start

1. Extract this folder.
2. Open PowerShell in the `ThreatGuard_AI` folder.
3. Copy environment template:

   ```powershell
   Copy-Item .env.example .env
   ```

4. Open `.env` and change `MONGO_URI` password to match the Compose password. For a local demo, keep both as `change-this-local-password`, or change both consistently.
5. Start MongoDB, API and UI:

   ```powershell
   docker compose up --build -d
   ```

6. Check services:

   ```powershell
   docker compose ps
   docker compose logs backend
   ```

7. Open:
   - Streamlit UI: http://localhost:8501
   - API docs: http://localhost:8000/docs
   - Health: http://localhost:8000/health
   - Metrics: http://localhost:8000/metrics

## Enable local Ollama model

The Compose file keeps Ollama optional so a machine without enough RAM can still run the API and inspect retrieval-only mode.

```powershell
docker compose --profile local-llm up -d ollama
docker exec -it threatguard-ollama ollama pull llama3.2:3b
docker exec -it threatguard-ollama ollama pull nomic-embed-text
```

Then set in `.env`:

```env
LLM_BACKEND=ollama
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_CHAT_MODEL=llama3.2:3b
OLLAMA_EMBED_MODEL=nomic-embed-text
```

Restart backend:

```powershell
docker compose up -d --force-recreate backend
```

If the local model cannot be downloaded or started, the app still returns a clearly labelled retrieval-only fallback; it does not pretend an LLM ran.

## Optional hosted LLM

Set `LLM_BACKEND=openai` and `OPENAI_API_KEY` in `.env`. Keep the key private. The OpenAI SDK is included in `requirements.txt`. Rebuild the backend after changing dependencies. Do not commit `.env`.

## Test the API

If `APP_API_KEY` is set, send it as `X-API-Key`. Example with PowerShell:

```powershell
$headers = @{ "X-API-Key" = "change-this-demo-api-key" }
$body = @{
  message = "Summarize active Windows threats and safe mitigations"
  session_id = "balaji-demo"
  platform = "Windows"
  status = "All"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://localhost:8000/chat -Headers $headers -ContentType "application/json" -Body $body
```

List threat records:

```powershell
Invoke-RestMethod http://localhost:8000/threats
```

Get persistent chat history:

```powershell
Invoke-RestMethod http://localhost:8000/sessions/balaji-demo -Headers $headers
```

Ingest an advisory:

```powershell
$doc = @{
  doc_id = "vendor-advisory-001"
  title = "Example vendor security advisory"
  text = "Paste the advisory text here. Include affected versions, fixed versions, severity, and remediation notes."
  platform = "Windows"
  source_url = "https://msrc.microsoft.com/update-guide/"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://localhost:8000/ingest -Headers $headers -ContentType "application/json" -Body $doc
```

## MongoDB Atlas Vector Search (optional)

The default Docker configuration stores embeddings in MongoDB and performs cosine ranking in the API so the lab can run locally without Atlas. To use MongoDB Atlas `$vectorSearch`:

1. Use a MongoDB Atlas cluster and set `MONGO_URI` to its connection string.
2. Start Ollama and pull the configured embedding model so all stored vectors use one consistent dimension.
3. Create an Atlas Vector Search index named `vector_index` on collection `knowledge`, with `embedding` configured as a vector field and dimensions matching your embedding model (for `nomic-embed-text`, verify the model's actual output dimension before creating the index).
4. Set `MONGODB_ATLAS_VECTOR_SEARCH=true` and `VECTOR_INDEX_NAME=vector_index` in `.env`.
5. Re-ingest knowledge documents after changing embedding models; vectors from different models/dimensions must not be mixed.

If Atlas vector search fails, the API logs a warning and falls back to local cosine retrieval. Do not claim Atlas search was demonstrated unless the Atlas index was created and queried successfully.

## Read-only inventory

The API endpoint `/scan/local` describes the container, not the Windows host. To inventory the host Python environment, run:

```powershell
python scripts/host_inventory.py
```

It only reports operating-system and Python-package metadata. It does not prove that the host is vulnerable and does not change system settings.

## Stop / reset

```powershell
docker compose down
```

To remove the database volume as well (this deletes local application data):

```powershell
docker compose down -v
```

## Threat lifecycle definitions

- Anticipated: emerging risk or exposure requiring monitoring; not a confirmed incident.
- Active: currently reported/confirmed by the cited source; applicability still needs version verification.
- Evolving: new information, affected versions, severity or mitigations are changing.
- Resolved: a fix or mitigation is reported; confirm that the target system actually received it.

These statuses in the sample data are illustrative labels, not a real-time feed.

## Security and production notes

- `.env` is excluded from Git. Use unique secrets outside classroom demos.
- Do not expose MongoDB to the public Internet.
- TLS/HTTPS is not enabled in the local classroom Compose profile. For production, place the app behind a TLS-terminating reverse proxy (for example, Caddy or Nginx) with a valid certificate and domain; do not expose the development ports directly. Also configure least-privilege database users and a managed secrets store.
- The included rate limiter is process-local and suitable only for a single-instance demonstration. Use a shared store/API gateway for multi-instance deployments.
- No automatic remediation is performed. Recommendations require human review and approval.
- The MongoDB vector records are stored as arrays and cosine-ranked locally. For Atlas production use, create a vector search index matching the embedding dimensions produced by the selected embedding model and use `$vectorSearch`.

## Submission evidence checklist

Capture your own screenshots after running:
1. `docker compose ps` showing healthy services.
2. Streamlit UI with platform/status filters.
3. A chat answer showing retrieved source evidence and the actual provider label.
4. `/health` response.
5. `/metrics` response.
6. MongoDB collections (`threats`, `knowledge`, `sessions`) with records.
7. API docs `/docs`.
8. Test output from `pytest -q`.

Do not claim screenshots or tests that you have not actually produced.
