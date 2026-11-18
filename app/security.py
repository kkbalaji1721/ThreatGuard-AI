import time
from collections import defaultdict, deque
from fastapi import Header, HTTPException
from .config import APP_API_KEY, RATE_LIMIT_PER_MINUTE

_requests = defaultdict(deque)

def require_api_key(x_api_key: str | None = Header(default=None)):
    # For a classroom local demo, an empty key disables auth. Set APP_API_KEY in .env.
    if APP_API_KEY and x_api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")

def check_rate_limit(client_id: str):
    now = time.time()
    q = _requests[client_id]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MINUTE:
        raise HTTPException(status_code=429, detail="Rate limit exceeded; try again later")
    q.append(now)
