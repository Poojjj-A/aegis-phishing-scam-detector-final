"""
tactics.py
-----------
Detects which stage of a social-engineering escalation a single message
belongs to. Long-con scams (romance scams, "pig butchering" investment
scams, fake recruiters) rarely ask for money in message one - they build
rapport and trust first, then isolate the victim, then introduce an
"opportunity", then ask for money, then escalate the ask. Tagging each
message with its tactic is what lets conversation_engine.py detect the
*shape* of a scam across a thread, not just risky wording in one message.
"""

import re
from dataclasses import dataclass

TACTIC_PATTERNS = {
    "rapport_building": {
        "label": "Rapport building",
        "description": "Friendly, personal small talk with no ask - the opening phase of trust-building.",
        "patterns": [
            r"\bhow (was|is) your day\b", r"\byou seem (really|so)\b", r"\bi (really )?like talking to you\b",
            r"\bwhat do you do for fun\b", r"\btell me about yourself\b", r"\byou'?re (so |very )?(sweet|kind|funny|interesting)\b",
            r"\bnice to meet you\b", r"\bgood morning\b", r"\bgood night\b", r"\bhope you'?re (doing )?well\b",
        ],
    },
    "trust_deepening": {
        "label": "Trust / sympathy building",
        "description": "Personal backstory or vulnerability shared to create emotional closeness and obligation.",
        "patterns": [
            r"\bi'?ve never told (anyone|this to anyone)\b", r"\bi feel like i can trust you\b",
            r"\bi'?m (a widow|widowed|lonely|going through a hard time)\b", r"\bsince (we met|talking to you)\b",
            r"\byou'?re different from (everyone|others)\b", r"\bi lost my (wife|husband|family)\b",
            r"\bmy (late )?(wife|husband) passed\b", r"\bi don'?t (usually|normally) (talk|share) (like this|this much)\b",
            r"\bsoulmate\b", r"\bmeant to (find|meet) (each other|you)\b",
        ],
    },
    "isolation": {
        "label": "Isolation tactic",
        "description": "Asks to move off-platform or keep the conversation secret - cuts off outside perspective.",
        "patterns": [
            r"\bdon'?t tell (anyone|your (family|friends|bank))\b", r"\bkeep this (between us|private|a secret)\b",
            r"\bmove (this|our chat) to (whatsapp|telegram|signal)\b", r"\bour (little )?secret\b",
            r"\bdelete this (chat|conversation|message)\b", r"\bthey wouldn'?t understand\b",
        ],
    },
    "opportunity_pitch": {
        "label": "Opportunity / investment pitch",
        "description": "Introduces a job, investment, or trading 'opportunity' that sounds too good to pass up.",
        "patterns": [
            r"\bguaranteed (profit|returns|income)\b", r"\bdouble your money\b", r"\btrading platform\b",
            r"\binvestment opportunity\b", r"\bpassive income\b", r"\bcrypto (trading|wallet|investment)\b",
            r"\bearn \$?\d+.*(day|week)\b", r"\bwork from home\b.*\bearn\b", r"\bexclusive (opportunity|access)\b",
            r"\bmy (broker|advisor|mentor) (says|told me)\b",
        ],
    },
    "urgency_pressure": {
        "label": "Urgency / pressure",
        "description": "Creates time pressure so the target acts before thinking it through.",
        "patterns": [
            r"\bact now\b", r"\blast chance\b", r"\bwindow (is|will be) closing\b", r"\bonly (today|a few hours) left\b",
            r"\bbefore it'?s too late\b", r"\bhurry\b", r"\btime[- ]sensitive\b", r"\bright now\b.{0,15}\bor\b",
        ],
    },
    "financial_ask": {
        "label": "Direct financial ask",
        "description": "Explicitly requests money, gift cards, crypto, or account/payment details.",
        "patterns": [
            r"\bcan you (send|wire|transfer)\b", r"\bneed (you to send|\$)\b", r"\bgift card\b",
            r"\bsend (me )?\$?\d", r"\btop up\b", r"\bwallet address\b", r"\bwire transfer\b",
            r"\bloan me\b", r"\bcover the fee\b", r"\bcustoms fee\b", r"\bprocessing fee\b",
        ],
    },
    "escalation": {
        "label": "Escalating the ask",
        "description": "Asks for more, after an initial smaller amount was already given - the classic 'one more time' push.",
        "patterns": [
            r"\bjust a (little )?bit more\b", r"\bone (last|more) time\b", r"\bfinal (push|amount|step)\b",
            r"\bi promise (this|it'?s) the last\b", r"\bto (unlock|release) (the|your) (funds|money)\b",
            r"\ba little more (and|to)\b", r"\bwe'?re so close\b",
        ],
    },
}

TACTIC_ORDER = [
    "rapport_building", "trust_deepening", "isolation",
    "opportunity_pitch", "urgency_pressure", "financial_ask", "escalation",
]


@dataclass
class TacticMatch:
    key: str
    label: str
    description: str
    hits: int


def detect_tactics(text: str) -> list[TacticMatch]:
    text_lower = text.lower()
    matches = []
    for key in TACTIC_ORDER:
        info = TACTIC_PATTERNS[key]
        hits = sum(1 for p in info["patterns"] if re.search(p, text_lower))
        if hits:
            matches.append(TacticMatch(key=key, label=info["label"], description=info["description"], hits=hits))
    return matches


def dominant_tactic(text: str) -> TacticMatch | None:
    matches = detect_tactics(text)
    if not matches:
        return None
    return max(matches, key=lambda m: m.hits)
