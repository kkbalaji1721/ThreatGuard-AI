

import logging
import platform as host_platform
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pymongo import MongoClient
from pymongo.errors import PyMongoError

from .config import MONGO_URI, MONGO_DB, LOG_LEVEL
from .embeddings import embed_text, cosine
from .llm import generate_answer
from .schemas import ChatRequest, IngestRequest
from .security import require_api_key, check_rate_limit
from .threats import load_sample_threats, normalize_threat

# ---------------------------------------------------------------------------
# Application setup and observability
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("threatguard")

app = FastAPI(
    title="ThreatGuard AI API",
    description=(
        "MongoDB-backed, defensive threat-intelligence assistant. "
        "Sample records are educational examples, not a live threat feed."
    ),
    version="1.0.0",
)

CHAT_COUNT = Counter("threatguard_chat_requests_total", "Number of chat requests")
LLM_ERRORS = Counter("threatguard_llm_errors_total", "Number of LLM provider errors")
REQUEST_LATENCY = Histogram(
    "threatguard_request_latency_seconds",
    "Request processing latency in seconds",
    ["endpoint"],
)

mongo_client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=5000,
)
database = mongo_client[MONGO_DB]


def get_db():
    """Return the configured MongoDB database."""
    return database


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _knowledge_text(threat: dict[str, Any]) -> str:
    return (
        f"Threat ID: {threat.get('threat_id', 'Not provided')}\n"
        f"CVE ID: {threat.get('cve_id', 'N/A')}\n"
        f"Title: {threat.get('title', 'Not provided')}\n"
        f"Platform: {threat.get('platform', 'Not provided')}\n"
        f"Status: {threat.get('status', 'Not provided')}\n"
        f"Severity: {threat.get('severity', 'Not provided')}\n"
        f"Summary: {threat.get('summary', 'Not provided')}\n"
        f"Mitigation: {threat.get('mitigation', 'Not provided')}\n"
        f"Source URL: {threat.get('source_url', 'Not provided')}\n"
        "Dataset note: Curated educational sample; not a verified live threat feed."
    )


def _seed_knowledge_if_empty(db) -> None:
    """Create one searchable knowledge record per threat only when empty."""
    if db.knowledge.count_documents({}) > 0:
        return

    for threat in db.threats.find({}, {"_id": 0}):
        text = _knowledge_text(threat)
        vector, provider = embed_text(text)
        db.knowledge.insert_one({
            "doc_id": threat.get("threat_id", "sample"),
            "chunk_id": 0,
            "title": threat.get("title", "Threat record"),
            "text": text,
            "platform": threat.get("platform", "All"),
            "source_url": threat.get("source_url", ""),
            "embedding": vector,
            "embedding_provider": provider,
            "created_at": utc_now(),
        })


@app.on_event("startup")
def startup_event():
    """Create indexes and seed sample data only when the collections are empty."""
    try:
        db = get_db()
        db.command("ping")
        db.threats.create_index("threat_id")
        db.knowledge.create_index([("doc_id", 1), ("chunk_id", 1)])
        db.sessions.create_index([("session_id", 1), ("timestamp", 1)])

        if db.threats.count_documents({}) == 0:
            samples = [normalize_threat(item) for item in load_sample_threats()]
            if samples:
                db.threats.insert_many(samples)
                logger.info("Inserted %s educational sample threat records", len(samples))

        _seed_knowledge_if_empty(db)
        logger.info("ThreatGuard startup completed; MongoDB is connected")
    except Exception:
        # The health endpoint will report the database problem. Do not erase or
        # recreate existing data when startup encounters a transient issue.
        logger.exception("ThreatGuard startup database initialization failed")


@app.on_event("shutdown")
def shutdown_event():
    mongo_client.close()


# ---------------------------------------------------------------------------
# Health, metrics and threat records
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"service": "ThreatGuard AI", "status": "running", "docs": "/docs"}


@app.get("/health")
def health():
    mongodb_ok = False
    try:
        get_db().command("ping")
        mongodb_ok = True
    except Exception:
        logger.exception("MongoDB health check failed")

    return {
        "status": "ok" if mongodb_ok else "degraded",
        "mongodb": mongodb_ok,
        "database": MONGO_DB,
        "timestamp": utc_now(),
    }


@app.get("/metrics")
def metrics():
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/threats", dependencies=[Depends(require_api_key)])
def list_threats(
    platform: str | None = None,
    status: str | None = None,
    limit: int = 100,
):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    filt: dict[str, Any] = {}
    if platform and platform != "All":
        filt["platform"] = {"$in": [platform, "All"]}
    if status and status != "All":
        filt["status"] = status

    records = list(
        get_db().threats.find(filt, {"_id": 0}).sort("threat_id", 1).limit(limit)
    )
    return {"count": len(records), "threats": records}


# ---------------------------------------------------------------------------
# Retrieval and RAG
# ---------------------------------------------------------------------------

def retrieve(
    query: str,
    platform_filter: str = "All",
    status_filter: str = "All",
    limit: int = 4,
):
    """Retrieve relevant knowledge chunks using cosine similarity.

    Each knowledge chunk is checked against the authoritative threats
    collection so platform and lifecycle filters are applied to threat records.
    """
    query_vector, embedding_provider = embed_text(query)
    db = get_db()
    scored: list[dict[str, Any]] = []

    for doc in db.knowledge.find({"embedding": {"$exists": True}}, {"_id": 0}):
        doc_platform = doc.get("platform", "All")
        if platform_filter != "All" and doc_platform not in (platform_filter, "All"):
            continue

        threat_id = doc.get("doc_id")
        threat = db.threats.find_one(
            {"threat_id": threat_id},
            {"_id": 0},
        )

        # Some ingested documents are not threat records. They remain eligible
        # for retrieval, but platform filtering still applies to their metadata.
        if threat:
            if platform_filter != "All" and threat.get("platform") not in (platform_filter, "All"):
                continue
            if status_filter != "All" and threat.get("status") != status_filter:
                continue
        elif status_filter != "All":
            # A generic ingested advisory has no lifecycle field to validate.
            continue

        score = cosine(query_vector, doc.get("embedding", []))
        item = dict(doc)
        item["score"] = float(score)
        if threat:
            item.update({
                "threat_id": threat.get("threat_id"),
                "cve_id": threat.get("cve_id", "N/A"),
                "title": threat.get("title", item.get("title", "Not provided")),
                "platform": threat.get("platform", item.get("platform", "All")),
                "status": threat.get("status", "Not provided"),
                "severity": threat.get("severity", "Not provided"),
                "summary": threat.get("summary", "Not provided"),
                "mitigation": threat.get("mitigation", "Not provided"),
                "source_url": threat.get("source_url", item.get("source_url", "")),
            })
        else:
            item.setdefault("threat_id", item.get("doc_id", "document"))
            item.setdefault("source_url", "")
        scored.append(item)

    scored.sort(key=lambda item: item.get("score", 0.0), reverse=True)
    return scored[:limit], embedding_provider


def _format_threat_context(threat: dict[str, Any], retrieved_item: dict[str, Any]) -> str:
    return (
        f"Threat ID: {threat.get('threat_id', retrieved_item.get('threat_id', 'Not provided'))}\n"
        f"CVE ID: {threat.get('cve_id', retrieved_item.get('cve_id', 'N/A'))}\n"
        f"Title: {threat.get('title', retrieved_item.get('title', 'Not provided'))}\n"
        f"Platform: {threat.get('platform', retrieved_item.get('platform', 'Not provided'))}\n"
        f"Status: {threat.get('status', retrieved_item.get('status', 'Not provided'))}\n"
        f"Severity: {threat.get('severity', retrieved_item.get('severity', 'Not provided'))}\n"
        f"Summary: {threat.get('summary', retrieved_item.get('summary', 'Not provided'))}\n"
        f"Mitigation: {threat.get('mitigation', retrieved_item.get('mitigation', 'Not provided'))}\n"
        f"Source URL: {threat.get('source_url', retrieved_item.get('source_url', 'Not provided'))}\n"
        "Dataset note: Curated educational sample; not a verified live threat feed.\n"
        f"Retrieved knowledge excerpt: {retrieved_item.get('text', '')}"
    )


# ---------------------------------------------------------------------------
# Chat endpoint
# ---------------------------------------------------------------------------

@app.post("/chat", dependencies=[Depends(require_api_key)])
def chat(payload: ChatRequest, request: Request):
    started = time.perf_counter()
    db = get_db()

    check_rate_limit(request.client.host if request.client else "unknown")

    now = utc_now()
    db.sessions.insert_one({
        "session_id": payload.session_id,
        "role": "user",
        "content": payload.message,
        "platform": payload.platform,
        "status": payload.status,
        "timestamp": now,
    })

    question = payload.message.lower()
    listing_phrases = (
        "show all",
        "list all",
        "display all",
        "give me all",
        "show me all",
        "all threats",
    )
    is_listing = any(phrase in question for phrase in listing_phrases)

    # If the user names a ThreatGuard ID, use an exact MongoDB lookup first.
    # Do not let semantic search substitute a different, similar-looking record.
    threat_id_match = re.search(
        r"\bTG-[A-Z0-9]+-\d+\b",
        payload.message,
        re.IGNORECASE,
    )
    requested_threat_id = (
        threat_id_match.group(0).upper() if threat_id_match else None
    )

    if requested_threat_id:
        threat = db.threats.find_one(
            {"threat_id": requested_threat_id},
            {"_id": 0},
        )

        if threat is None:
            answer = (
                f"No matching threat record was found for Threat ID "
                f"{requested_threat_id} in the knowledge base. "
                "I cannot provide a CVE ID, severity, or mitigation "
                "for a threat record that does not exist."
            )
            retrieved = []
            llm_provider = "mongodb-exact-lookup"
            embedding_provider = "not-used"

        elif (
            (payload.platform != "All"
             and threat.get("platform") not in (payload.platform, "All"))
            or
            (payload.status != "All"
             and threat.get("status") != payload.status)
        ):
            answer = (
                f"Threat ID {requested_threat_id} exists in the knowledge base, "
                "but it does not match the selected platform or status filters. "
                "Change the filters to view this record."
            )
            retrieved = []
            llm_provider = "mongodb-exact-lookup"
            embedding_provider = "not-used"

        else:
            evidence = _knowledge_text(threat)
            retrieved_item = {
                "score": 1.0,
                "threat_id": threat.get("threat_id"),
                "cve_id": threat.get("cve_id", "N/A"),
                "title": threat.get("title", "Not provided"),
                "platform": threat.get("platform", "Not provided"),
                "status": threat.get("status", "Not provided"),
                "severity": threat.get("severity", "Not provided"),
                "summary": threat.get("summary", "Not provided"),
                "mitigation": threat.get("mitigation", "Not provided"),
                "source_url": threat.get("source_url", "Not provided"),
                "text": evidence,
            }
            retrieved = [retrieved_item]
            context = _format_threat_context(threat, retrieved_item)
            answer, llm_provider = generate_answer(
                payload.message,
                context,
                [],
            )
            embedding_provider = "not-used"

    elif is_listing:
        # A listing request must use MongoDB directly, not top-k vector search
        # or an LLM that could invent records.
        filt: dict[str, Any] = {}
        if payload.platform != "All":
            filt["platform"] = {"$in": [payload.platform, "All"]}
        if payload.status != "All":
            filt["status"] = payload.status

        records = list(
            db.threats.find(filt, {"_id": 0}).sort("threat_id", 1)
        )
        retrieved = []
        for threat in records:
            evidence = _knowledge_text(threat)
            retrieved.append({
                "score": 1.0,
                "threat_id": threat.get("threat_id"),
                "cve_id": threat.get("cve_id", "N/A"),
                "title": threat.get("title", "Not provided"),
                "platform": threat.get("platform", "Not provided"),
                "status": threat.get("status", "Not provided"),
                "severity": threat.get("severity", "Not provided"),
                "summary": threat.get("summary", "Not provided"),
                "mitigation": threat.get("mitigation", "Not provided"),
                "source_url": threat.get("source_url", "Not provided"),
                "text": evidence,
            })

        if not retrieved:
            answer = (
                "No matching threat records were found in the knowledge base "
                "for the selected filters."
            )
        else:
            lines = [
                "The following threat records were found in the MongoDB knowledge base:"
            ]
            for index, item in enumerate(retrieved, 1):
                lines.append(
                    f"{index}. Threat ID: {item['threat_id']}\n"
                    f"   CVE ID: {item['cve_id']}\n"
                    f"   Platform: {item['platform']}\n"
                    f"   Status: {item['status']}\n"
                    f"   Severity: {item['severity']}\n"
                    f"   Summary: {item['summary']}\n"
                    f"   Mitigation: {item['mitigation']}\n"
                    f"   Source: {item['source_url']}"
                )
            answer = "\n\n".join(lines)

        llm_provider = "mongodb-grounded"
        embedding_provider = "not-used"

    else:
        retrieved, embedding_provider = retrieve(
            payload.message,
            payload.platform,
            payload.status,
        )

        context_parts = []
        for item in retrieved:
            threat = db.threats.find_one(
                {"threat_id": item.get("threat_id")},
                {"_id": 0},
            ) or {}
            context_parts.append(_format_threat_context(threat, item))

        context = "\n\n".join(context_parts)
        answer, llm_provider = generate_answer(
            payload.message,
            context,
            [],
        )

    if "fallback" in llm_provider or llm_provider == "provider-error":
        LLM_ERRORS.inc()

    db.sessions.insert_one({
        "session_id": payload.session_id,
        "role": "assistant",
        "content": answer,
        "timestamp": utc_now(),
        "llm_provider": llm_provider,
        "retrieved_ids": [item.get("threat_id") for item in retrieved],
    })

    CHAT_COUNT.inc()
    REQUEST_LATENCY.labels(endpoint="/chat").observe(time.perf_counter() - started)

    return {
        "session_id": payload.session_id,
        "answer": answer,
        "llm_provider": llm_provider,
        "embedding_provider": embedding_provider,
        "sources": retrieved,
        "notice": (
            "Threat records include curated educational examples. "
            "Verify live status with the original vendor/advisory source."
        ),
    }


# ---------------------------------------------------------------------------
# Document ingestion, session history, statistics and local inventory
# ---------------------------------------------------------------------------

@app.post("/ingest", dependencies=[Depends(require_api_key)])
def ingest(payload: IngestRequest, request: Request):
    check_rate_limit(request.client.host if request.client else "unknown")

    db = get_db()
    chunk_size = 1200
    overlap = 150
    chunks = []
    start = 0
    text = payload.text.strip()

    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)

    # Replace only chunks belonging to this exact document ID.
    db.knowledge.delete_many({"doc_id": payload.doc_id})

    inserted = []
    for index, chunk in enumerate(chunks):
        vector, provider = embed_text(chunk)
        inserted.append({
            "doc_id": payload.doc_id,
            "chunk_id": index,
            "title": payload.title,
            "text": chunk,
            "platform": payload.platform,
            "source_url": payload.source_url,
            "embedding": vector,
            "embedding_provider": provider,
            "created_at": utc_now(),
        })

    if inserted:
        db.knowledge.insert_many(inserted)

    return {
        "status": "ingested",
        "doc_id": payload.doc_id,
        "chunks_created": len(inserted),
        "embedding_providers": sorted({item["embedding_provider"] for item in inserted}),
    }


@app.get("/sessions/{session_id}", dependencies=[Depends(require_api_key)])
def get_session(session_id: str, limit: int = 100):
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    messages = list(
        get_db().sessions.find(
            {"session_id": session_id},
            {"_id": 0},
        ).sort("timestamp", 1).limit(limit)
    )
    return {"session_id": session_id, "count": len(messages), "messages": messages}


@app.get("/stats", dependencies=[Depends(require_api_key)])
def stats():
    db = get_db()
    by_platform = list(db.threats.aggregate([
        {"$group": {"_id": "$platform", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]))
    by_status = list(db.threats.aggregate([
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]))
    return {
        "threat_count": db.threats.count_documents({}),
        "knowledge_count": db.knowledge.count_documents({}),
        "session_message_count": db.sessions.count_documents({}),
        "threats_by_platform": by_platform,
        "threats_by_status": by_status,
    }


@app.get("/scan/local", dependencies=[Depends(require_api_key)])
def scan_local():
    """Read-only inventory of the API container/runtime, not the Windows host."""
    return {
        "scan_type": "read-only runtime inventory",
        "hostname": socket.gethostname(),
        "operating_system": host_platform.system(),
        "os_release": host_platform.release(),
        "machine": host_platform.machine(),
        "python_version": host_platform.python_version(),
        "note": (
            "This describes the application container/runtime only. "
            "It does not scan for vulnerabilities or modify system settings."
        ),
        "timestamp": utc_now(),
    }
