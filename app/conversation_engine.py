"""
conversation_engine.py
------------------------
Analyzes a multi-message conversation thread, not just one message in
isolation. This is what catches "long-con" scams (romance scams, fake
investment/job recruiters) that deliberately spread the manipulation across
many messages so no single one looks dangerous on its own.

Two things happen that a single-message scan can't do:
  1. Every message is tagged with its manipulation tactic (see tactics.py),
     so the *shape* of the conversation is visible - not just its content.
  2. A message's score can be boosted by what came before it: a financial
     ask that follows earlier rapport/trust-building messages is scored
     higher than the same ask would be on its own, because that sequence
     is itself the red flag.
"""

from dataclasses import dataclass, field

from app.risk_engine import assess, RiskFlag
from app.tactics import detect_tactics, TACTIC_ORDER

# Tactics that, if seen earlier in the thread, make a later financial ask
# or escalation message more suspicious - because that sequence is exactly
# how long-con scams are structured.
SETUP_TACTICS = {"rapport_building", "trust_deepening", "isolation", "opportunity_pitch"}
PAYOFF_TACTICS = {"financial_ask", "escalation"}

CONTEXT_BOOST = 22


@dataclass
class MessageResult:
    index: int
    text: str
    risk_score: int
    risk_level: str
    tactics: list
    context_boosted: bool
    flags: list

    def to_dict(self):
        return {
            "index": self.index,
            "text": self.text,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "tactics": [{"key": t.key, "label": t.label, "description": t.description} for t in self.tactics],
            "context_boosted": self.context_boosted,
            "flags": [f.__dict__ for f in self.flags],
        }


def _risk_level(score: int) -> str:
    if score >= 65:
        return "Dangerous"
    if score >= 35:
        return "Suspicious"
    if score >= 15:
        return "Low Risk"
    return "Safe"


def analyze_thread(messages: list[str]) -> dict:
    seen_setup_tactics = set()
    results: list[MessageResult] = []

    for i, text in enumerate(messages):
        text = (text or "").strip()
        base = assess(text)
        tactics = detect_tactics(text)
        tactic_keys = {t.key for t in tactics}

        context_boosted = False
        score = base.risk_score
        flags = list(base.flags)

        # Does this message make a payoff move (ask for money / escalate),
        # after earlier messages already laid the groundwork?
        if tactic_keys & PAYOFF_TACTICS and seen_setup_tactics:
            context_boosted = True
            score = min(100, score + CONTEXT_BOOST)
            setup_labels = ", ".join(sorted(seen_setup_tactics))
            flags.insert(0, RiskFlag(
                severity="high", source="context",
                message=(
                    f"This request follows earlier {setup_labels.replace('_', ' ')} messages in this "
                    "conversation - that build-up-then-ask pattern is a hallmark of long-con scams."
                ),
            ))

        seen_setup_tactics |= (tactic_keys & SETUP_TACTICS)

        results.append(MessageResult(
            index=i, text=text, risk_score=score, risk_level=_risk_level(score),
            tactics=tactics, context_boosted=context_boosted, flags=flags,
        ))

    scores = [r.risk_score for r in results]
    escalation_detected = False
    escalation_note = ""
    if len(scores) >= 3:
        early_avg = sum(scores[:max(1, len(scores) // 3)]) / max(1, len(scores) // 3)
        late_avg = sum(scores[-max(1, len(scores) // 3):]) / max(1, len(scores) // 3)
        if late_avg - early_avg >= 20:
            escalation_detected = True
            escalation_note = (
                f"Risk climbed from an average of {early_avg:.0f} early in the conversation to "
                f"{late_avg:.0f} later on - consistent with a scam that builds trust before asking for money."
            )

    return {
        "messages": [r.to_dict() for r in results],
        "scores": scores,
        "escalation_detected": escalation_detected,
        "escalation_note": escalation_note,
        "peak_score": max(scores) if scores else 0,
        "peak_index": scores.index(max(scores)) if scores else -1,
    }
