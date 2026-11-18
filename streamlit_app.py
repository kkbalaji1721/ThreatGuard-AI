
import os
import uuid
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://localhost:8000")
API_KEY = os.getenv("APP_API_KEY", "")
headers = {"X-API-Key": API_KEY} if API_KEY else {}

st.set_page_config(
    page_title="ThreatGuard AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ThreatGuard AI")
st.caption(
    "Multi-platform threat intelligence assistant · "
    "defensive decision support"
)

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

if "messages" not in st.session_state:
    st.session_state.messages = []

with st.sidebar:
    st.header("Assessment filters")

    platform = st.selectbox(
        "Platform",
        ["All", "Windows", "Linux", "macOS", "Android", "iOS"]
    )

    status = st.selectbox(
        "Threat lifecycle",
        ["All", "Anticipated", "Active", "Evolving", "Resolved"]
    )

    st.caption(
        "Sample records are educational examples. "
        "Confirm live applicability with vendor advisories."
    )

    if st.button("New conversation"):
        st.session_state.session_id = str(uuid.uuid4())
        st.session_state.messages = []
        st.rerun()

    try:
        health = requests.get(
            f"{API_URL}/health",
            timeout=3
        ).json()

        st.write("API:", health.get("status"))
        st.write(
            "MongoDB:",
            "Connected" if health.get("mongodb") else "Unavailable"
        )

    except Exception:
        st.warning("Backend is not reachable. Start Docker Compose.")

# Display conversation history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

        if msg["role"] == "assistant" and msg.get("provider"):
            st.caption(msg["provider"])

        if msg["role"] == "assistant" and msg.get("sources"):
            with st.expander("View source references"):
                for source in msg["sources"]:
                    st.markdown(f"**{source.get('title', 'Source')}**")

                    if source.get("source_url"):
                        st.markdown(
                            f"[Open source advisory]({source['source_url']})"
                        )

# Chat input
prompt = st.chat_input(
    "Ask about a CVE, platform risk, threat status or mitigation..."
)

if prompt:
    st.session_state.messages.append({
        "role": "user",
        "content": prompt
    })

    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        try:
            response = requests.post(
                f"{API_URL}/chat",
                headers=headers,
                json={
                    "message": prompt,
                    "session_id": st.session_state.session_id,
                    "platform": platform,
                    "status": status
                },
                timeout=150
            )

            response.raise_for_status()
            data = response.json()

            answer = data["answer"]
            provider = (
                f"LLM: {data['llm_provider']} · "
                f"Embeddings: {data['embedding_provider']}"
            )

            st.markdown(answer)
            st.caption(provider)

            sources = data.get("sources", [])

            if sources:
                with st.expander("View source references"):
                    for source in sources:
                        st.markdown(
                            f"**{source.get('title', 'Source')}**"
                        )

                        if source.get("source_url"):
                            st.markdown(
                                f"[Open source advisory]({source['source_url']})"
                            )

            st.session_state.messages.append({
                "role": "assistant",
                "content": answer,
                "provider": provider,
                "sources": sources
            })

        except Exception as e:
            answer = (
                f"Request failed: {type(e).__name__}. "
                "Check backend health and configuration."
            )

            st.error(answer)

            st.session_state.messages.append({
                "role": "assistant",
                "content": answer
            })
