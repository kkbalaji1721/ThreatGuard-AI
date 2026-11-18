import hashlib, math, re
import requests
from .config import OLLAMA_BASE_URL, OLLAMA_EMBED_MODEL

def _hash_embedding(text: str, dims: int = 256):
    # Deterministic local fallback. This is feature hashing, not a learned semantic model.
    vec = [0.0] * dims
    tokens = re.findall(r"[a-zA-Z0-9_.-]+", text.lower())
    for token in tokens:
        idx = int(hashlib.sha256(token.encode()).hexdigest()[:8], 16) % dims
        vec[idx] += 1.0
    norm = math.sqrt(sum(v*v for v in vec)) or 1.0
    return [v/norm for v in vec]

def embed_text(text: str):
    try:
        r = requests.post(
            f"{OLLAMA_BASE_URL}/api/embed",
            json={"model": OLLAMA_EMBED_MODEL, "input": text},
            timeout=20,
        )
        r.raise_for_status()
        emb = r.json().get("embeddings", [[]])[0]
        if emb:
            return emb, "ollama"
    except Exception:
        pass
    return _hash_embedding(text), "feature-hashing-fallback"

def cosine(a, b):
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x*y for x, y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(y*y for y in b))
    return dot / (na*nb) if na and nb else 0.0
