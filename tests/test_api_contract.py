from app.schemas import ChatRequest, IngestRequest

def test_chat_request_defaults():
    req = ChatRequest(message="Explain CVE-2024-30078")
    assert req.platform == "All"
    assert req.status == "All"
    assert req.session_id == "demo"

def test_chat_request_rejects_unknown_platform():
    try:
        ChatRequest(message="Check this issue", platform="Solaris")
        assert False
    except Exception:
        assert True

def test_ingest_request():
    req = IngestRequest(doc_id="doc1",title="Test advisory",text="A sufficiently long advisory text for validation.")
    assert req.doc_id == "doc1"
