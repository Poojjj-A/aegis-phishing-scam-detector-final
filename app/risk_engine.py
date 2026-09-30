"""
risk_engine.py
---------------
Combines three signal sources into one final 0-100 risk score:
  1. ML model probability (TF-IDF + Logistic Regression) - catches
     patterns learned from the training corpus as a whole.
  2. Text heuristics (features.py) - catches known phishing language
     patterns explicitly, even for wording the model hasn't seen.
  3. URL heuristics (url_analysis.py) - catches structurally suspicious
     links regardless of the surrounding message wording.

The blend is deliberately weighted so that a message can be flagged as
dangerous even if the ML model is unsure, as long as strong rule-based
red flags (e.g. a typosquatted bank domain + a credential request) are
present - and vice versa. Every flag returned is traceable to a specific
signal, so the output is fully explainable rather than a black-box number.
"""

from dataclasses import dataclass, field

from app.features import analyze_text
from app.url_analysis import analyze_all_urls
from app import model as ml_model

ML_WEIGHT = 0.5
TEXT_WEIGHT = 0.3
URL_WEIGHT = 0.2


@dataclass
class RiskFlag:
    severity: str   # "high" | "medium" | "low"
    source: str     # "ml" | "text" | "url"
    message: str


@dataclass
class RiskResult:
    risk_score: int
    risk_level: str
    ml_probability: float
    heuristic_text_score: int
    heuristic_url_score: int
    flags: list = field(default_factory=list)
    urls: list = field(default_factory=list)
    top_ml_terms: list = field(default_factory=list)

    def to_dict(self):
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "ml_probability": round(self.ml_probability, 3),
            "heuristic_text_score": self.heuristic_text_score,
            "heuristic_url_score": self.heuristic_url_score,
            "flags": [f.__dict__ for f in self.flags],
            "urls": self.urls,
            "top_ml_terms": [{"term": t, "weight": round(w, 3)} for t, w in self.top_ml_terms],
        }


def _risk_level(score: int) -> str:
    if score >= 65:
        return "Dangerous"
    if score >= 35:
        return "Suspicious"
    if score >= 15:
        return "Low Risk"
    return "Safe"


def _severity_for(score_contribution: int) -> str:
    if score_contribution >= 20:
        return "high"
    if score_contribution >= 10:
        return "medium"
    return "low"


def assess(text: str) -> RiskResult:
    text = (text or "").strip()
    flags: list[RiskFlag] = []

    # --- Text heuristics ---
    text_finding = analyze_text(text)
    for f in text_finding.flags:
        flags.append(RiskFlag(severity="medium", source="text", message=f))

    # --- URL heuristics ---
    url_findings = analyze_all_urls(text)
    url_score = 0
    url_details = []
    for uf in url_findings:
        url_score = max(url_score, uf.score)  # worst-of, not sum, to avoid over-punishing many links
        url_details.append({"url": uf.url, "score": uf.score, "flags": uf.flags})
        for f in uf.flags:
            flags.append(RiskFlag(severity=_severity_for(uf.score), source="url", message=f"[{uf.url}] {f}"))

    # --- ML model ---
    try:
        ml_proba = ml_model.predict_proba(text) if text else 0.0
        top_terms = ml_model.top_contributing_terms(text) if text else []
    except Exception:
        # Fail-safe: if the model isn't available for any reason, degrade
        # gracefully to heuristics-only rather than crashing the request.
        ml_proba = 0.0
        top_terms = []

    if top_terms:
        readable = ", ".join(f"'{t}'" for t, _ in top_terms[:4])
        flags.append(RiskFlag(
            severity="medium", source="ml",
            message=f"Language model flagged wording statistically associated with scams: {readable}",
        ))

    # --- Blend into final score ---
    final = (
        ML_WEIGHT * (ml_proba * 100)
        + TEXT_WEIGHT * text_finding.score
        + URL_WEIGHT * url_score
    )
    final_score = int(round(min(100, max(0, final))))

    # Safety override: if nothing at all was flagged and there's no text,
    # don't report a nonzero "Safe-but-not-zero" score.
    if not text:
        final_score = 0

    level = _risk_level(final_score)

    # Sort flags: high severity first for readability
    order = {"high": 0, "medium": 1, "low": 2}
    flags.sort(key=lambda f: order.get(f.severity, 3))

    return RiskResult(
        risk_score=final_score,
        risk_level=level,
        ml_probability=ml_proba,
        heuristic_text_score=text_finding.score,
        heuristic_url_score=url_score,
        flags=flags,
        urls=url_details,
        top_ml_terms=top_terms,
    )
