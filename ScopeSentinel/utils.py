import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def safe_str(x: Any) -> str:
    if x is None:
        return ""
    try:
        return str(x)
    except Exception:
        return ""


def normalize_text(x: str) -> str:
    return re.sub(r"\s+", " ", (x or "")).strip().lower()


def strip_trailing_punct(s: str) -> str:
    return s.rstrip('''."'),;:!?)]}''')


def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return re.findall(r"(https?://[^\s\"\'\)\]]+)", text)


def extract_host(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urlparse(strip_trailing_punct(url))
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def normalize_host(host: str) -> str:
    host = (host or "").lower().strip()
    if host.startswith("www."):
        return host[4:]
    return host


def host_matches_rule(host: str, rule: str) -> bool:
    h = normalize_host(host)
    r = normalize_host(rule)

    if not h or not r:
        return False

    if r.startswith("*."):
        suffix = r[2:]
        return h == suffix or h.endswith("." + suffix)

    return h == r


def find_first_match(text: str, patterns: List[str]) -> Optional[str]:
    t = text or ""
    for p in patterns:
        if re.search(p, t, re.IGNORECASE):
            return p
    return None


def try_parse_json_like_text(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    return None


def cheap_text_overlap(a: str, b: str) -> float:
    """
    很粗糙但通用的 token overlap。
    用来判断输入值是否明显来自 prompt 内容。
    """
    aa = set(re.findall(r"[a-zA-Z0-9_@./:-]{2,}", normalize_text(a)))
    bb = set(re.findall(r"[a-zA-Z0-9_@./:-]{2,}", normalize_text(b)))

    if not aa or not bb:
        return 0.0

    inter = aa & bb
    union = aa | bb
    return len(inter) / max(len(union), 1)