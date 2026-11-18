# Assessment mapping: Final Assessment A.1–A.7

| Faculty section | Project implementation | Verification |
|---|---|---|
| A.1 LLM selection | Ollama chat backend; optional OpenAI provider; truthful retrieval-only fallback | `LLM_BACKEND` in `.env`; ask a question and inspect `llm_provider` |
| A.2 ingestion and embeddings | `/ingest` chunks documents, requests Ollama embeddings, stores vectors in MongoDB; deterministic feature-hashing fallback if Ollama embeddings unavailable | POST `/ingest`; inspect `knowledge` collection |
| A.3 FastAPI RAG | `/chat` retrieves top-scoring stored chunks and sends context/history to configured LLM | POST `/chat`; inspect sources |
| A.4 conversation memory | `sessions` collection stores user and assistant messages with session IDs and timestamps | GET `/sessions/{session_id}` |
| A.5 frontend | Streamlit chat interface with platform and lifecycle filters | `http://localhost:8501` |
| A.6 containerization | Dockerfile + Compose services for MongoDB, API and Streamlit; optional Ollama profile | `docker compose ps` |
| A.7 hardening | `.env`, optional API-key auth, rate limiting, `/health`, `/metrics`, logging and graceful Mongo client close | health/metrics endpoints and invalid-key/rate-limit tests |

## Exercise concept coverage

- Exercise 2: MongoDB connection string and environment-based cloud/local configuration.
- Exercises 4–6: operational MongoDB queries, filtered reads, indexes, counts and aggregation-ready document schema.
- Exercise 12: credentials outside source code, `.env` excluded by `.gitignore`.
- Exercise 13: Dockerfile, Compose network, persistent volume and health checks.
- Exercise 14: request counters, latency histogram, health endpoint, logs and graceful shutdown.
- Exercise 17: document chunking, embeddings, vector storage, similarity retrieval and RAG prompt construction.

## Important technical limits

1. The included threat records are curated educational sample records, not a live threat feed. Always verify affected/fixed versions with the linked vendor source.
2. The default local fallback uses deterministic feature hashing, not a learned semantic embedding model. For vector-quality embeddings, run Ollama with `nomic-embed-text`; the API records which provider was used.
3. Local MongoDB cosine retrieval is implemented for Docker portability. An opt-in MongoDB Atlas `$vectorSearch` path is also implemented; it requires a matching Atlas vector index and consistent embedding dimensions.
4. `/scan/local` reports the application container/runtime. For a host inventory, run `python scripts/host_inventory.py` directly on the host. Neither scanner proves a vulnerability.
5. Remediation is advisory only. No system changes or automatic patching are performed.
6. A real LLM response requires Ollama with a pulled model or a configured hosted API key. Retrieval-only fallback is explicitly labelled.
