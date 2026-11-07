"""
Resilient JSON cleaner and parser for local LLM outputs.
Handles markdown code blocks, preamble text, trailing commas, single quotes,
and truncated JSON structures without crashing.
"""
import json
import re
from typing import Any, Dict, Optional

def clean_and_parse_json(raw_text: str) -> Optional[Dict[str, Any]]:
    """Clean and parse potentially malformed JSON text from local LLMs."""
    if not raw_text or not raw_text.strip():
        return None

    text = raw_text.strip()

    # 1. Extract content from markdown code fences if present
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    if code_block_match:
        text = code_block_match.group(1).strip()

    # 2. Extract outermost JSON object { ... } or array [ ... ]
    outer_match = re.search(r"(\{[\s\S]*\}|\[[\s\S]*\])", text)
    if outer_match:
        text = outer_match.group(1).strip()

    # 3. First attempt: standard json.loads
    try:
        return json.loads(text)
    except Exception:
        pass

    # 4. Remove trailing commas before closing braces/brackets
    sanitized = re.sub(r",\s*([\]}])", r"\1", text)
    try:
        return json.loads(sanitized)
    except Exception:
        pass

    # 5. Fix common single quotes to double quotes if valid json key/values
    # (Be cautious not to corrupt apostrophes in English text)
    sanitized_quotes = re.sub(r"(?<=[{\s,])'([a-zA-Z0-9_]+)'\s*:", r'"\1":', sanitized)
    try:
        return json.loads(sanitized_quotes)
    except Exception:
        pass

    # 6. Attempt repair of truncated JSON (unclosed brackets/braces)
    repaired = _repair_unclosed_json(sanitized)
    if repaired:
        try:
            return json.loads(repaired)
        except Exception:
            pass

    # 7. Fallback: regex search for finding objects inside the text
    return _extract_findings_fallback(raw_text)

def _repair_unclosed_json(text: str) -> Optional[str]:
    """Closes unclosed quotes, brackets, and braces from truncated generation."""
    stack = []
    in_string = False
    escape = False

    for char in text:
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char in "{[":
            stack.append(char)
        elif char == "}":
            if stack and stack[-1] == "{":
                stack.pop()
        elif char == "]":
            if stack and stack[-1] == "[":
                stack.pop()

    repaired = text
    if in_string:
        repaired += '"'

    # Close any open structures in reverse order
    while stack:
        opener = stack.pop()
        if opener == "{":
            repaired += "}"
        elif opener == "[":
            repaired += "]"

    return repaired

def _extract_findings_fallback(text: str) -> Dict[str, Any]:
    """Last-resort fallback to extract any findings-like dictionary from text."""
    findings = []
    # Search for attack_type occurrences
    pattern = re.compile(
        r'attack_type["\']?\s*:\s*["\']([^"\']+)["\'][\s\S]*?'
        r'severity["\']?\s*:\s*["\']([^"\']+)["\'][\s\S]*?'
        r'target_or_id["\']?\s*:\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    for match in pattern.finditer(text):
        findings.append({
            "id": f"fallback-{len(findings)+1}",
            "attack_type": match.group(1),
            "severity": match.group(2).capitalize(),
            "target_or_id": match.group(3),
            "evidence": [],
            "reason": "Extracted via resilient fallback parser from model output",
            "suggested_action": "Investigate entity activity across logs"
        })
    return {"findings": findings, "carried_state": {}}

