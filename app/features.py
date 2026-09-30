"""
features.py
------------
Rule-based linguistic signals that commonly appear in phishing, smishing and
scam messages: urgency, threats, reward-bait, credential harvesting
requests, generic greetings and shouty formatting. Each rule contributes a
bounded score and an explanation string, which the risk_engine later blends
with the ML model's judgement.
"""

import re
from dataclasses import dataclass, field

URGENCY_PATTERNS = [
    r"\bact now\b", r"\bact immediately\b", r"\burgent(ly)?\b", r"\bimmediate action\b",
    r"\bwithin\s+(24|12|2|3|6)\s*hours\b", r"\bexpires?\s+(today|soon|shortly)\b",
    r"\blast\s+(chance|warning|reminder)\b", r"\btime[- ]sensitive\b", r"\bdo not ignore\b",
    r"\brespond immediately\b", r"\bfinal notice\b",
]

THREAT_PATTERNS = [
    r"\baccount (will be|has been) (suspended|locked|terminated|restricted|closed)\b",
    r"\blegal action\b", r"\barrest(ed)?\b", r"\bpenalt(y|ies)\b", r"\bpolice\b",
    r"\bsuspended\b.{0,20}\bunless\b", r"\boverdue\b", r"\bfailure to (comply|respond|pay)\b",
    r"\bwarrant\b", r"\bfrozen\b",
]

REWARD_PATTERNS = [
    r"\byou('| ha)ve won\b", r"\bcongratulations\b", r"\bclaim your (prize|reward|gift)\b",
    r"\bfree (gift|money|prize|reward)\b", r"\blottery\b", r"\bcash prize\b",
    r"\bselected to receive\b", r"\bgift card\b", r"\bexclusive offer\b", r"\bwinner\b",
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\b(ssn|social security number)\b", r"\bone[- ]time (password|code)\b",
    r"\botp\b", r"\bpin\b", r"\bcard number\b", r"\bcvv\b", r"\bexpiry date\b",
    r"\bdate of birth\b", r"\bverify your (identity|account|details|information)\b",
    r"\bconfirm your (identity|account|details|password|information)\b",
    r"\bupdate your (payment|billing|account) (details|information)\b",
    r"\blogin credentials\b",
]

CTA_PATTERNS = [
    r"\bclick (here|the link|below)\b", r"\btap (here|the link|below)\b",
    r"\bfollow this link\b", r"\bopen the attachment\b", r"\bdownload (now|the attachment)\b",
    r"\bverify now\b", r"\blog ?in now\b",
]

GENERIC_GREETINGS = [
    r"\bdear (customer|user|valued customer|member|sir/madam|account holder)\b",
    r"\bhello dear\b", r"\bdear beneficiary\b",
]

FINANCIAL_TERMS = [
    r"\bbank\b", r"\baccount\b", r"\bpayment\b", r"\binvoice\b", r"\brefund\b",
    r"\btax\b", r"\bwire transfer\b", r"\bbitcoin\b", r"\bcrypto\b", r"\bwallet\b",
    r"\bIRS\b", r"\bpaypal\b", r"\bdirect deposit\b", r"\bbilling\b",
]

IMPERSONATION_BRANDS = [
    "irs", "amazon", "apple", "microsoft", "netflix", "paypal", "usps", "fedex",
    "ups", "dhl", "bank of america", "wells fargo", "chase", "facebook",
    "instagram", "whatsapp", "linkedin", "google", "coinbase", "binance",
    "social security administration",
]


@dataclass
class TextFinding:
    score: int = 0
    flags: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)


def _count_hits(patterns, text_lower):
    hits = []
    for p in patterns:
        if re.search(p, text_lower):
            hits.append(p)
    return hits


def analyze_text(text: str) -> TextFinding:
    finding = TextFinding()
    text_lower = text.lower()
    words = re.findall(r"[A-Za-z']+", text)

    # --- Urgency language ---
    hits = _count_hits(URGENCY_PATTERNS, text_lower)
    if hits:
        finding.score += min(20, 8 * len(hits))
        finding.flags.append("Uses urgency/pressure language to rush the reader into acting without thinking")

    # --- Threats ---
    hits = _count_hits(THREAT_PATTERNS, text_lower)
    if hits:
        finding.score += min(25, 10 * len(hits))
        finding.flags.append("Contains threatening language (suspension, legal action, penalties) to intimidate the reader")

    # --- Reward / prize bait ---
    hits = _count_hits(REWARD_PATTERNS, text_lower)
    if hits:
        finding.score += min(22, 9 * len(hits))
        finding.flags.append("Promises an unexpected prize, refund or reward - a classic scam lure")

    # --- Credential / PII harvesting requests ---
    hits = _count_hits(CREDENTIAL_PATTERNS, text_lower)
    if hits:
        finding.score += min(30, 10 * len(hits))
        finding.flags.append("Directly asks for sensitive information (password, OTP, card details, SSN, etc.)")

    # --- Call-to-action link/attachment pressure ---
    hits = _count_hits(CTA_PATTERNS, text_lower)
    if hits:
        finding.score += min(15, 6 * len(hits))
        finding.flags.append("Pushes the reader to click a link, tap a button, or open an attachment")

    # --- Generic greeting (mass-sent messages rarely know your name) ---
    hits = _count_hits(GENERIC_GREETINGS, text_lower)
    if hits:
        finding.score += 10
        finding.flags.append("Uses a generic greeting ('Dear Customer') instead of your actual name")

    # --- Brand impersonation combined with a request ---
    mentioned_brands = [b for b in IMPERSONATION_BRANDS if b in text_lower]
    if mentioned_brands and (hits or _count_hits(CREDENTIAL_PATTERNS, text_lower) or _count_hits(THREAT_PATTERNS, text_lower)):
        finding.score += 15
        finding.flags.append(
            f"Claims to be from a well-known organisation ({', '.join(mentioned_brands[:2])}) while pressuring the reader"
        )

    # --- Financial terms density ---
    fin_hits = _count_hits(FINANCIAL_TERMS, text_lower)
    finding.stats["financial_terms"] = len(fin_hits)

    # --- ALL-CAPS ratio ---
    cap_words = [w for w in words if len(w) > 2 and w.isupper()]
    cap_ratio = len(cap_words) / max(1, len(words))
    if cap_ratio > 0.15 and len(words) > 5:
        finding.score += 10
        finding.flags.append("Excessive use of ALL CAPS, a common attention-grabbing scam tactic")
    finding.stats["caps_ratio"] = round(cap_ratio, 3)

    # --- Exclamation mark spam ---
    exclam = text.count("!")
    if exclam >= 3:
        finding.score += 8
        finding.flags.append("Excessive exclamation marks used to create false excitement or urgency")
    finding.stats["exclamations"] = exclam

    # --- Money amounts mentioned ---
    if re.search(r"[\$₹€£]\s?\d[\d,\.]*|\b\d[\d,\.]*\s?(usd|dollars|rupees|inr)\b", text_lower):
        finding.score += 6
        finding.flags.append("Mentions a specific monetary amount")

    finding.score = min(finding.score, 100)
    return finding
