"""
url_analysis.py
----------------
Heuristic analysis of URLs found inside a message. Each check is a small,
independent signal that real phishing/smishing links tend to exhibit. We
never fetch the URL (no network calls) - everything is inferred from the
string itself, so this is fast, safe, and works fully offline.
"""

import re
from urllib.parse import urlparse
from dataclasses import dataclass, field

# A short, well-known set of link shorteners frequently abused to hide the
# real destination of a phishing link.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in",
    "s.id", "v.gd", "qr.ae",
}

# TLDs that are cheap/free to register and disproportionately used in
# throwaway phishing infrastructure. This is a heuristic, not a verdict.
SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "work", "country", "gq", "ml", "tk",
    "cf", "ga", "loan", "men", "rest", "mom", "win", "stream", "icu",
    "buzz", "quest", "cam", "cyou", "monster",
}

SENSITIVE_URL_KEYWORDS = {
    "login", "verify", "secure", "account", "update", "confirm", "billing",
    "signin", "reset", "unlock", "suspend", "recover", "authenticate",
    "wallet", "invoice",
}

# A small reference set of frequently-impersonated brand domains, used only
# to flag look-alike domains (typosquats), e.g. "paypa1.com" or
# "amaz0n-secure.com". This list is intentionally short and easy to extend.
PROTECTED_BRANDS = (
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "netflix.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "irs.gov", "usps.com", "fedex.com", "ups.com", "dhl.com", "facebook.com",
    "instagram.com", "whatsapp.com", "linkedin.com", "outlook.com",
    "coinbase.com", "binance.com",
)  # a tuple (fixed order) so results are deterministic between runs

URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\.)[^\s<>"']+|[a-z0-9\-]+\.(?:com|net|org|gov|
    edu|io|co|info|biz|xyz|top|click|work|tk|ml|gq|cf|ga|country|men|loan|
    rest|mom|win|stream|icu|buzz|quest|cam|cyou|monster)(?:/[^\s<>"']*)?)""",
    re.VERBOSE,
)

IP_HOST_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _levenshtein(a: str, b: str) -> int:
    """Plain edit-distance implementation (no external deps needed)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def extract_urls(text: str) -> list[str]:
    found = URL_REGEX.findall(text)
    # normalize + dedupe while preserving order
    seen, out = set(), []
    for u in found:
        u = u.strip().rstrip(".,);]'\"")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out


@dataclass
class UrlFinding:
    url: str
    score: int = 0                 # 0-100 contribution for this single URL
    flags: list = field(default_factory=list)  # human-readable reasons


def _normalize(url: str) -> str:
    if not re.match(r"^[a-zA-Z]+://", url):
        url = "http://" + url
    return url


def analyze_url(raw_url: str) -> UrlFinding:
    finding = UrlFinding(url=raw_url)
    url = _normalize(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path_and_query = (parsed.path or "") + "?" + (parsed.query or "")

    if not host:
        return finding

    # 1. Bare IP address instead of a domain name
    if IP_HOST_REGEX.match(host):
        finding.score += 30
        finding.flags.append("Link points to a raw IP address instead of a domain name")

    # 2. Known URL shortener - real destination is hidden
    if host in URL_SHORTENERS:
        finding.score += 20
        finding.flags.append(f"Uses the link shortener '{host}', which hides the real destination")

    # 3. Suspicious / low-cost TLD
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        finding.score += 15
        finding.flags.append(f"Domain uses the '.{tld}' extension, commonly abused for throwaway scam sites")

    # 4. '@' in the URL - browsers ignore everything before '@' when resolving the host
    if "@" in raw_url:
        finding.score += 25
        finding.flags.append("URL contains '@', a classic trick to disguise the real destination")

    # 5. Excessive subdomains ("paypal.com.verify-login.ru")
    host_parts = host.split(".")
    if len(host_parts) > 4:
        finding.score += 15
        finding.flags.append("Unusually long chain of subdomains, often used to bury the real domain")

    # 6. No HTTPS
    if parsed.scheme == "http":
        finding.score += 8
        finding.flags.append("Link does not use HTTPS")

    # 7. Sensitive keywords in path/host trying to look official
    kw_hits = [k for k in SENSITIVE_URL_KEYWORDS if k in host.replace("-", "") or k in path_and_query.lower()]
    if kw_hits:
        finding.score += min(20, 6 * len(kw_hits))
        finding.flags.append(
            "URL text uses account/security-related words (" + ", ".join(sorted(set(kw_hits))[:4]) + ") to appear legitimate"
        )

    # 8. Excessive hyphens in domain (brand-secure-login-verify.com)
    if host.count("-") >= 3:
        finding.score += 12
        finding.flags.append("Domain name is padded with many hyphens, a common obfuscation pattern")

    # 9. Brand look-alike / typosquat detection
    registrable = ".".join(host_parts[-2:]) if len(host_parts) >= 2 else host
    for brand in ([] if registrable in PROTECTED_BRANDS else PROTECTED_BRANDS):
        # (if the registrable domain IS a protected brand, it's the real site: skip)
        dist = _levenshtein(registrable, brand)
        if 0 < dist <= 2 and abs(len(registrable) - len(brand)) <= 3:
            finding.score += 35
            finding.flags.append(f"Domain '{registrable}' closely mimics the trusted domain '{brand}' (possible typosquat)")
            break
        if brand.split(".")[0] in host_parts[:-2] or (len(host_parts) > 2 and brand.split(".")[0] in host_parts[0]):
            # brand name stuffed into a subdomain of an unrelated domain
            finding.score += 30
            finding.flags.append(f"Brand name '{brand.split('.')[0]}' is stuffed into a subdomain of an unrelated domain")
            break

    # 10. Overly long URL (often used to obscure structure / evade quick review)
    if len(raw_url) > 75:
        finding.score += 8
        finding.flags.append("Unusually long URL, which can hide the true destination from a quick glance")

    finding.score = min(finding.score, 100)
    return finding


def analyze_all_urls(text: str) -> list[UrlFinding]:
    return [analyze_url(u) for u in extract_urls(text)]
