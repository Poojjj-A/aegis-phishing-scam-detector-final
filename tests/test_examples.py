"""
test_examples.py
------------------
Sanity checks that the risk engine scores clearly-phishing and clearly-legit
messages on the correct side of the fence. These are not exhaustive
statistical evaluations (see train_model.py's held-out report for that) -
they're a fast smoke test you can run with `pytest` before every deploy.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.risk_engine import assess

PHISHING_EXAMPLES = [
    "Dear Customer, your Apple account has been suspended due to unusual activity. "
    "Verify your identity immediately at apple-verify-id.top or your account will be closed within 24 hours.",

    "URGENT: Your bank account will be frozen due to unusual activity. Verify your PIN and SSN "
    "immediately at bit.ly/3xVerify to avoid legal action.",

    "Congratulations! You have won a $1000 Amazon gift card. Claim now at amaz0n-support.net "
    "before it expires!!!",
]

LEGIT_EXAMPLES = [
    "Hey, are we still on for lunch tomorrow at 1pm? Let me know if that works for you.",
    "Your order #48213 has shipped and is expected to arrive on Thursday.",
    "Here's the shared doc we discussed: https://www.google.com/document/edit",
]


def test_phishing_examples_score_high():
    for text in PHISHING_EXAMPLES:
        result = assess(text)
        assert result.risk_score >= 40, f"Expected elevated risk for: {text[:50]}... got {result.risk_score}"
        assert result.risk_level in ("Suspicious", "Dangerous")
        assert len(result.flags) > 0


def test_legit_examples_score_low():
    for text in LEGIT_EXAMPLES:
        result = assess(text)
        assert result.risk_score < 40, f"Expected low risk for: {text[:50]}... got {result.risk_score}"
        assert result.risk_level in ("Safe", "Low Risk")


def test_empty_input_is_safe():
    result = assess("")
    assert result.risk_score == 0
    assert result.risk_level == "Safe"


def test_thread_detects_escalation_and_boosts_context():
    from app.conversation_engine import analyze_thread
    thread = [
        "Hi! I saw your profile, hope you don't mind me messaging. How was your day?",
        "I don't usually share this much but I feel like I can trust you. I lost my wife last year.",
        "Please don't tell your friends about us yet, this is just between us.",
        "My broker has a crypto trading platform with guaranteed returns, you should try it too.",
        "Can you send $500 to get started? I promise I will guide you through everything.",
        "We're so close, I just need a little bit more, say $2000, to release the funds.",
    ]
    result = analyze_thread(thread)
    assert result["escalation_detected"] is True
    scores = result["scores"]
    assert scores[-1] > scores[0]
    last_msg = result["messages"][-1]
    assert last_msg["context_boosted"] is True
    tactic_keys = {t["key"] for m in result["messages"] for t in m["tactics"]}
    assert "rapport_building" in tactic_keys
    assert "financial_ask" in tactic_keys or "escalation" in tactic_keys


if __name__ == "__main__":
    test_phishing_examples_score_high()
    test_legit_examples_score_low()
    test_empty_input_is_safe()
    test_thread_detects_escalation_and_boosts_context()
    print("All smoke tests passed.")
