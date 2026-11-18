from pydantic import BaseModel, Field
from typing import Literal

Platform = Literal["Windows", "Linux", "macOS", "Android", "iOS", "All"]

class ChatRequest(BaseModel):
    message: str = Field(min_length=2, max_length=2000)
    session_id: str = Field(default="demo", min_length=1, max_length=100)
    platform: Platform = "All"
    status: Literal["All", "Anticipated", "Active", "Evolving", "Resolved"] = "All"

class IngestRequest(BaseModel):
    doc_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=250)
    text: str = Field(min_length=20, max_length=50000)
    platform: Platform = "All"
    source_url: str = ""
