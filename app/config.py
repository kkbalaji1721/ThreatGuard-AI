import os
from dotenv import load_dotenv
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "threatguard")
LLM_BACKEND = os.getenv("LLM_BACKEND", "ollama").lower()
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_CHAT_MODEL = os.getenv("OLLAMA_CHAT_MODEL", "llama3.2:3b")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
APP_API_KEY = os.getenv("APP_API_KEY", "")
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "20"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

MONGODB_ATLAS_VECTOR_SEARCH = os.getenv("MONGODB_ATLAS_VECTOR_SEARCH", "false").lower() == "true"
VECTOR_INDEX_NAME = os.getenv("VECTOR_INDEX_NAME", "vector_index")
