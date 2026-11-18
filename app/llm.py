import re
import requests

from .config import (
    LLM_BACKEND,
    OLLAMA_BASE_URL,
    OLLAMA_CHAT_MODEL,
    OPENAI_API_KEY,
    OPENAI_MODEL,
)


SYSTEM_PROMPT = """
You are ThreatGuard AI, a defensive cybersecurity and threat-intelligence assistant.

RESPONSE RULES:
1. Explain concepts in simple, beginner-friendly words.
2. For general educational questions (for example, definitions of threats,
   vulnerabilities, ransomware, phishing, or basic protection), answer the
   concept directly using general cybersecurity knowledge.
3. Do not force an unrelated knowledge-base record into a general answer.
4. Use supplied knowledge-base evidence for specific ThreatGuard records,
   CVEs, platforms, statuses, severities, and record-specific mitigations.
5. Never invent ThreatGuard IDs, CVEs, sources, or record-specific facts.
6. Preserve the exact platform, status, and severity when discussing a record.
7. "Active" does not mean active exploitation.
8. "Resolved" does not mean every device is patched.
9. Never claim a device is compromised or affected without evidence.
10. Educational records are examples, not a verified live threat feed.
11. For protection advice, recommend safe defensive practices such as updates,
    backups, multi-factor authentication, cautious handling of links and files,
    and reputable security tools.
12. If a specific fact is not supported by the knowledge base, say so clearly.

Do not provide instructions for carrying out cyberattacks or deploying malware.
"""


def extract_field(context: str, field: str):
    labels = (
        r"Threat ID|CVE ID|CVE|Platform|Status|Severity|"
        r"Summary|Mitigation|Source URL|Source|Title|Dataset note|"
        r"Retrieved knowledge excerpt"
    )

    pattern = (
        rf"(?i)(?:^|\s){re.escape(field)}\s*:\s*"
        rf"(.*?)(?=\s+(?:{labels})\s*:|$)"
    )

    match = re.search(pattern, context, re.DOTALL)

    if match:
        return match.group(1).strip().strip(".,;")

    return None


def grounded_threat_answer(context: str):
    fields = {
        "Threat ID": extract_field(context, "Threat ID"),
        "CVE ID": extract_field(context, "CVE ID"),
        "Platform": extract_field(context, "Platform"),
        "Status": extract_field(context, "Status"),
        "Severity": extract_field(context, "Severity"),
        "Summary": extract_field(context, "Summary"),
        "Mitigation": extract_field(context, "Mitigation"),
        "Source URL": extract_field(context, "Source URL")
        or extract_field(context, "Source"),
    }

    if not fields["Summary"] and not fields["Mitigation"]:
        return None

    lines = [
        "Here is the explanation based on the retrieved knowledge-base record:",
        "",
    ]

    for key in ("Threat ID", "CVE ID", "Platform", "Status", "Severity"):
        if fields[key]:
            lines.append(f"**{key}:** {fields[key]}")

    if fields["Summary"]:
        lines.extend([
            "",
            "**What is the threat?**",
            fields["Summary"],
        ])

    if fields["Mitigation"]:
        lines.extend([
            "",
            "**How to protect yourself:**",
            fields["Mitigation"],
        ])

    lines.extend([
        "",
        "**Important:** This record alone does not confirm that a particular "
        "device is affected, exploited, or patched. Check the official vendor "
        "advisory for applicability.",
    ])

    if fields["Source URL"]:
        lines.extend([
            "",
            f"**Source:** {fields['Source URL']}",
        ])

    return "\n".join(lines)


def _build_messages(question: str, context: str, history: list[dict]):
    """Build a prompt that separates general education from record-specific facts."""
    is_threat_id_question = bool(
        re.search(r"\bTG-[A-Z0-9]+-\d+\b", question, re.IGNORECASE)
    )

    if is_threat_id_question:
        user_prompt = (
            "The user asked about a specific ThreatGuard ID. Explain only the "
            "record supported by the supplied knowledge-base context. Do not "
            "add unsupported CVEs, status, severity, or threat details.\n\n"
            f"Knowledge-base context:\n{context or 'No matching record context was supplied.'}"
            f"\n\nQuestion: {question}"
        )
    else:
        user_prompt = (
            "Answer the user's question directly as a general cybersecurity "
            "learning question. Use simple language and give practical, safe "
            "defensive advice when relevant. The knowledge-base context below "
            "may contain an unrelated record: use it only if it directly helps "
            "answer the question. Do not turn a general question into a summary "
            "of an unrelated ThreatGuard record. Do not claim that the user's "
            "device is affected or compromised.\n\n"
            f"Optional knowledge-base context:\n{context or 'No relevant knowledge-base context was retrieved.'}"
            f"\n\nQuestion: {question}"
        )

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    # Include a small amount of prior conversation when it is provided.
    for item in (history or [])[-6:]:
        role = item.get("role")
        content = item.get("content")
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            messages.append({"role": role, "content": content[:2000]})

    messages.append({"role": "user", "content": user_prompt})
    return messages


def generate_answer(question: str, context: str, history: list[dict]):
    # Only an explicit ThreatGuard ID request should use the fixed record
    # formatter. General questions must reach the language model.
    is_threat_id_question = bool(
        re.search(r"\bTG-[A-Z0-9]+-\d+\b", question, re.IGNORECASE)
    )

    if is_threat_id_question and context.strip():
        grounded_answer = grounded_threat_answer(context)
        if grounded_answer:
            return grounded_answer, "knowledge-base-grounded"

    msgs = _build_messages(question, context, history)

    if LLM_BACKEND == "openai" and OPENAI_API_KEY:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=OPENAI_API_KEY)

            out = client.chat.completions.create(
                model=OPENAI_MODEL,
                messages=msgs,
                temperature=0,
                max_tokens=700,
            )

            answer = out.choices[0].message.content or ""
            if answer.strip():
                return answer, "openai"

        except Exception as e:
            return (
                f"LLM provider error ({type(e).__name__}). "
                "Please check the configured language-model service.",
                "provider-error",
            )

    if LLM_BACKEND == "ollama":
        try:
            r = requests.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": OLLAMA_CHAT_MODEL,
                    "messages": msgs,
                    "stream": False,
                    "options": {"temperature": 0},
                },
                timeout=120,
            )

            r.raise_for_status()
            answer = r.json().get("message", {}).get("content", "")

            if answer.strip():
                return answer, "ollama"

        except Exception as e:
            return (
                f"Ollama provider error ({type(e).__name__}). "
                "Please check that the Ollama service and chat model are available.",
                "provider-error",
            )

    return (
        "The configured language model is unavailable. "
        "Please check the LLM_BACKEND setting and the model service.",
        "retrieval-only-fallback",
    )
