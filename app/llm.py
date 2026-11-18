



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
You are ThreatGuard AI, a defensive threat-intelligence assistant.

STRICT RULES:
1. Use only supplied knowledge-base evidence for specific threat facts.
2. Never invent threat IDs, CVEs, technical details, sources or impacts.
3. Preserve exact platform, status and severity.
4. Active does not mean active exploitation.
5. Resolved does not mean every device is patched.
6. Never claim a vulnerability is exploitable unless evidence says so.
7. Never invent attacker capabilities or attack consequences.
8. Never claim a device is compromised without evidence.
9. Explain applicability limitations.
10. Educational records are not verified live threat intelligence.

Explain things in simple words.
If information is missing, say it is not provided.
"""


def extract_field(context: str, field: str):
    labels = (
        r"Threat ID|CVE ID|CVE|Platform|Status|Severity|"
        r"Summary|Mitigation|Source|Title|Dataset note|"
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
        "Source": extract_field(context, "Source"),
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
        "**Important:** This record alone does not confirm that a particular device is affected, exploited, or patched. Check the official vendor advisory for applicability.",
    ])

    if fields["Source"]:
        lines.extend([
            "",
            f"**Source:** {fields['Source']}",
        ])

    return "\n".join(lines)


def generate_answer(question: str, context: str, history: list[dict]):

    if context.strip():
        grounded_answer = grounded_threat_answer(context)

        if grounded_answer:
            return grounded_answer, "knowledge-base-grounded"

    prompt = (
        "Use only the supplied knowledge-base evidence for specific facts.\n\n"
        f"Knowledge context:\n"
        f"{context or 'No matching knowledge documents were retrieved.'}"
        f"\n\nQuestion: {question}"
    )

    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

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

            return out.choices[0].message.content, "openai"

        except Exception as e:
            return (
                f"LLM provider error ({type(e).__name__}). "
                "The retrieved evidence is available below.",
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

        except Exception:
            pass

    if context.strip():
        answer = (
            "The LLM is unavailable. Here is the retrieved evidence:\n\n"
            + context[:3500]
            + "\n\nVerify applicability with the original vendor advisory."
        )
    else:
        answer = (
            "No matching knowledge-base evidence was retrieved. "
            "I cannot confirm a threat from this query."
        )

    return answer, "retrieval-only-fallback"
