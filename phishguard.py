"""
PhishGuard v2.0 — Multi-Signal Scoring Engine
==============================================
Production-grade upgrade over Phase 6. Detection is now layered:

  Signal Layer 1 — Keyword matching       (per-category weighted scores)
  Signal Layer 2 — Combo boost logic      (dangerous category combinations)
  Signal Layer 3 — Linguistic signals     (imperative tone, urgency phrases)
  Signal Layer 4 — Safe-pattern defence   (negation / awareness phrases)
  Signal Layer 5 — URL intelligence       (TLD abuse, brand impersonation,
                                           hyphenated fake domains)

Scoring thresholds:
  >= 70  → is_scam = True,  status = "scam"
  >= 40  → is_scam = False, status = "suspicious"
  <  40  → is_scam = False, status = "safe"

New output fields (backward-compatible):
  primary_category, secondary_categories, confidence_score, url_risk_flags,
  status, safe_signals_detected

Existing fields preserved:
  is_scam, risk_score, category, red_flags, impact, action,
  explanation_markdown, detected_urls, url_analysis,
  matched_categories, matched_keywords, user_message, user_action
"""

import re
import json
import sys
import uvicorn
import tldextract
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

# =============================================================================
# App
# =============================================================================

app = FastAPI(
    title="PhishGuard API",
    description="Multi-signal phishing & scam detection engine",
    version="2.0.0",
)

# Allow all origins so the HTML frontend can call the API from any port
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Language Templates  (Phase 6 — unchanged)
# =============================================================================

LANGUAGE_TEMPLATES = {
    "en": {
        "scam":        "⚠️ This appears to be a scam.",
        "suspicious":  "🔶 This message looks suspicious.",
        "safe":        "✅ This looks safe.",
        "action":      "Do not click any links or share sensitive information.",
    },
    "hi": {
        "scam":        "⚠️ यह एक धोखाधड़ी लगती है।",
        "suspicious":  "🔶 यह संदिग्ध लगता है।",
        "safe":        "✅ यह सुरक्षित लगता है।",
        "action":      "किसी भी लिंक पर क्लिक न करें या निजी जानकारी साझा न करें।",
    },
    "mr": {
        "scam":        "⚠️ हे फसवणूक असू शकते.",
        "suspicious":  "🔶 हे संशयास्पद वाटते.",
        "safe":        "✅ हे सुरक्षित वाटते.",
        "action":      "कोणत्याही लिंकवर क्लिक करू नका किंवा वैयक्तिक माहिती देऊ नका.",
    },
}

# =============================================================================
# Request Schema
# =============================================================================

class DetectRequest(BaseModel):
    """Payload for /detect. Supply text, url, or both. Language defaults to 'en'."""
    text:     Optional[str] = None
    url:      Optional[str] = None
    language: Optional[str] = "en"

# =============================================================================
# ─── SIGNAL LAYER 0: URL Helpers ─────────────────────────────────────────────
# =============================================================================

_URL_RE = re.compile(
    r"https?://(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """Return all http/https URLs found in text. Treats bare URL input as single-element list."""
    text = text.strip()
    if re.match(r"^https?://\S+$", text, re.IGNORECASE):
        return [text]
    return _URL_RE.findall(text)


def parse_url(url: str) -> dict:
    """Decompose a URL into domain parts via tldextract."""
    ext = tldextract.extract(url)
    return {
        "full_url":  url,
        "domain":    ext.domain,
        "subdomain": ext.subdomain,
        "suffix":    ext.suffix,
    }

# =============================================================================
# ─── SIGNAL LAYER 1: Keyword Patterns ────────────────────────────────────────
# =============================================================================

SCAM_PATTERNS = {
    "upi_scam": [
        "upi collect", "collect request", "payment request",
        "approve payment", "pay to receive",
        "wrong transfer", "mistakenly transferred",
        "return the money", "send back money",
        "share upi pin", "enter upi pin",
        # Hindi
        "पेमेंट रिक्वेस्ट", "यूपीआई पिन", "पैसे वापस करें", "गलती से ट्रांसफर",
    ],
    "otp_scam": [
        "share otp", "enter otp", "verification code",
        "transaction otp", "bank otp", "otp for verification",
        # Hindi
        "ओटीपी शेयर करें", "ओटीपी दर्ज करें", "ओटीपी बताएं", "वेरिफिकेशन कोड",
    ],
    "bank_scam": [
        "account blocked", "account suspended",
        "kyc expired", "update kyc",
        "reactivate account", "verify account", "verify your account",
        "unblock account", "suspicious activity",
        # Hindi
        "खाता बंद", "केवाईसी अपडेट", "kyc अपडेट", "बैंक खाता बंद",
        "अकाउंट ब्लॉक", "खाता निलंबित",
    ],
    "urgency": [
        "urgent", "immediately", "action required",
        "within 24 hours", "act now", "last chance",
        "expires soon", "avoid penalty",
        # Hindi
        "तुरंत", "अभी करें", "जल्दी करें", "अंतिम मौका",
        "24 घंटे में", "अभी क्लिक करें",
    ],
    "prize_scam": [
        "you have won", "you won", "won a prize", "won ₹",
        "cash prize", "lucky draw", "lucky winner",
        "claim your prize", "claim prize", "claim now",
        "reward money", "processing fee",
        # Hindi
        "आपने जीता", "₹5000 जीता", "इनाम जीता", "लकी ड्रा",
        "पुरस्कार जीता", "अभी क्लेम करें", "नकद पुरस्कार",
    ],
    "tax_scam": [
        "income tax refund", "refund pending",
        "pan blocked", "link aadhaar",
        "verify pan", "tax department", "claim refund",
        # Hindi
        "आयकर रिफंड", "पैन ब्लॉक", "आधार लिंक", "रिफंड लंबित",
    ],
    "delivery_scam": [
        "delivery failed", "parcel held", "address issue",
        "reschedule delivery", "redelivery", "confirm delivery", "delivery otp",
        # Hindi
        "डिलीवरी फेल", "पार्सल रोका", "पता सही करें",
    ],
    "loan_scam": [
        "instant loan", "loan approved", "loan in 5 minutes",
        "no credit check", "instant approval", "loan offer", "processing fee",
        # Hindi
        "तुरंत लोन", "लोन अप्रूव", "5 मिनट में लोन",
    ],
    "digital_arrest_scam": [
        "digital arrest", "arrest warrant", "case registered",
        "under investigation", "illegal parcel", "money laundering",
        "freeze account", "police case", "video call now", "prove innocence",
        # Hindi
        "डिजिटल अरेस्ट", "गिरफ्तारी वारंट", "मनी लॉन्ड्रिंग",
        "पुलिस केस", "निर्दोषिता साबित",
    ],
    "challan_scam": [
        "pending challan", "traffic violation", "pay fine",
        "license suspended", "unpaid fine", "vehicle violation", "e-challan link",
        # Hindi
        "चालान", "ई-चालान", "जुर्माना भरें", "लाइसेंस निलंबित",
    ],
    "scheme_scam": [
        "pm kisan", "pension benefit", "government scheme", "subsidy",
        "bonus payment", "extra payment", "verify aadhaar",
        # Hindi
        "सरकारी योजना", "सब्सिडी", "आधार वेरिफाई", "पेंशन लाभ", "पीएम किसान",
    ],
    "family_emergency_scam": [
        "road accident", "hospitalised", "medical emergency",
        "need urgent help", "send money urgently", "in hospital",
        # Hindi
        "सड़क दुर्घटना", "अस्पताल में", "मेडिकल इमरजेंसी", "तुरंत पैसे भेजें",
    ],
    "scholarship_scam": [
        "scholarship", "education grant", "student benefit", "claim scholarship",
        # Hindi
        "छात्रवृत्ति", "शिक्षा अनुदान",
    ],
}

# Per-category base weights (v2: tuned to reduce false positives at boundaries)
SCAM_WEIGHTS = {
    "upi_scam":              25,
    "otp_scam":              30,
    "bank_scam":             35,
    "urgency":               15,
    "prize_scam":            20,
    "tax_scam":              25,
    "delivery_scam":         20,
    "loan_scam":             20,
    "digital_arrest_scam":   40,
    "challan_scam":          20,
    "scheme_scam":           15,
    "family_emergency_scam": 25,
    "scholarship_scam":      15,
}

# Human-readable flag labels per category
CATEGORY_FLAG_LABELS = {
    "urgency":               "Contains urgent / pressure language",
    "otp_scam":              "Requests OTP or verification code",
    "upi_scam":              "Mentions UPI payment or PIN sharing",
    "prize_scam":            "Claims reward, prize, or lucky draw",
    "bank_scam":             "Threatens account block or KYC action",
    "tax_scam":              "References tax refund or PAN/Aadhaar",
    "delivery_scam":         "Mentions failed delivery or parcel issue",
    "loan_scam":             "Promises instant loan or approval",
    "digital_arrest_scam":   "Uses digital arrest or legal threat language",
    "challan_scam":          "Mentions traffic fine or e-challan",
    "scheme_scam":           "References government scheme or subsidy",
    "family_emergency_scam": "Claims family emergency requiring funds",
    "scholarship_scam":      "Mentions scholarship or education grant",
}

# =============================================================================
# ─── SIGNAL LAYER 2: Combo Boosts ────────────────────────────────────────────
# =============================================================================

# Each entry: (set_of_required_categories, trigger_keyword_or_None, boost_points, label)
COMBO_BOOSTS = [
    ({"bank_scam", "urgency"},           None,      20, "Bank threat + urgency combined"),
    ({"upi_scam"},                       "approve", 25, "UPI approve request — classic scam pattern"),
    ({"prize_scam"},                     "fee",     20, "Prize + fee demand — advance fee scam"),
    ({"prize_scam", "urgency"},          None,      25, "Prize claim + urgency — pressure scam"),
    ({"otp_scam", "bank_scam"},          None,      15, "OTP + bank threat — credential phishing"),
    ({"digital_arrest_scam", "urgency"}, None,      20, "Digital arrest + urgency — high-pressure scam"),
]


def apply_combo_boosts(categories: set, lowered_text: str) -> tuple[int, List[str]]:
    """
    Check all COMBO_BOOSTS rules.

    Returns (total_boost_points, list_of_triggered_combo_labels).
    """
    boost  = 0
    labels = []
    for required_cats, keyword, points, label in COMBO_BOOSTS:
        # All required categories must be present
        if not required_cats.issubset(categories):
            continue
        # Optional keyword check
        if keyword and keyword not in lowered_text:
            continue
        boost  += points
        labels.append(label)
    return boost, labels

# =============================================================================
# ─── SIGNAL LAYER 3: Linguistic Signals ──────────────────────────────────────
# =============================================================================

# Imperative verb patterns that increase confidence without adding full category weight
_IMPERATIVE_PATTERNS = re.compile(
    r"\b(click|call|send|pay|share|verify|confirm|update|submit|approve|transfer|download)\b",
    re.IGNORECASE,
)

_URGENCY_PHRASES = [
    "do not ignore", "failure to", "or else", "otherwise",
    "legal action", "consequences", "penalty", "blocked",
]


def detect_linguistic_signals(text: str) -> tuple[int, List[str]]:
    """
    Detect imperative tone and urgency amplifiers.

    Returns (score_boost, list_of_signal_labels).
    These are soft signals — they increase confidence but contribute
    only modestly to the raw score.
    """
    boost   = 0
    signals = []
    lowered = text.lower()

    imperatives = _IMPERATIVE_PATTERNS.findall(text)
    unique_imperatives = list({v.lower() for v in imperatives})
    if len(unique_imperatives) >= 2:
        boost += 10
        signals.append(f"Multiple imperative verbs detected: {', '.join(unique_imperatives[:4])}")

    for phrase in _URGENCY_PHRASES:
        if phrase in lowered:
            boost += 5
            signals.append(f"Urgency amplifier: '{phrase}'")
            break  # one amplifier flag per message is sufficient

    return boost, signals

# =============================================================================
# ─── SIGNAL LAYER 4: Safe Patterns (False Positive Reduction) ────────────────
# =============================================================================

SAFE_PATTERNS = [
    # Awareness / advisory phrases — the message is warning AGAINST sharing
    "do not share otp",
    "never share your otp",
    "bank will never ask",
    "never share your pin",
    "do not share your pin",
    "beware of fraud",
    "this is a scam",
    "report fraud",
    "protect yourself",
    "stay safe from",
    # Hindi awareness variants
    "ओटीपी किसी से साझा न करें",
    "बैंक कभी नहीं मांगता",
    "धोखाधड़ी से सावधान",
]

# Score reduction applied per safe pattern match
_SAFE_PATTERN_PENALTY = -30


def detect_safe_signals(text: str) -> tuple[int, List[str]]:
    """
    Scan for awareness / advisory phrases that indicate the message is
    ABOUT scams rather than being a scam itself.

    Returns (score_delta, list_of_matched_safe_patterns).
    Score delta is negative — it reduces the raw risk score.
    """
    lowered   = text.lower()
    reduction = 0
    matched   = []

    for pattern in SAFE_PATTERNS:
        if pattern in lowered:
            reduction += _SAFE_PATTERN_PENALTY
            matched.append(pattern)

    return reduction, matched

# =============================================================================
# ─── SIGNAL LAYER 5: URL Intelligence ────────────────────────────────────────
# =============================================================================

SUSPICIOUS_TLDS = {"xyz", "top", "gq", "tk", "ml", "cf", "click", "zip", "work", "ru"}

TRUSTED_BRANDS  = {"paytm", "phonepe", "gpay", "googlepay", "google", "amazon",
                   "flipkart", "sbi", "hdfc", "icici", "axis", "upi", "bank"}

# Official domain allow-list — these are genuine and must not be flagged
_OFFICIAL_DOMAINS = {
    "google", "amazon", "flipkart", "sbi", "hdfcbank",
    "icicibank", "axisbank", "paytm", "phonepe",
}


def analyze_url_risk(url_info: dict) -> dict:
    """
    Score a single parsed URL across three heuristics:
      1. Suspicious TLD
      2. Brand impersonation (brand name present but domain is NOT the official one)
      3. Hyphenated fake domain (e.g. "secure-login-paytm")

    Returns {"url_risk": int, "url_flags": list[str]}.
    """
    risk   = 0
    flags  = []
    domain = url_info["domain"].lower()
    suffix = url_info["suffix"].lower()

    # Skip official known-good domains entirely
    if domain in _OFFICIAL_DOMAINS:
        return {"url_risk": 0, "url_flags": []}

    # 1. Suspicious TLD
    if suffix in SUSPICIOUS_TLDS:
        risk += 25
        flags.append(f"Suspicious domain extension: .{suffix}")

    # 2. Brand impersonation — brand keyword in a non-official domain
    for brand in TRUSTED_BRANDS:
        if brand in domain and domain != brand:
            risk += 30
            flags.append(f"Possible brand impersonation: '{brand}' in domain")
            break  # one impersonation flag per URL

    # 3. Hyphenated structure signals fake "secure" domains
    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        risk += 15
        flags.append(f"Heavily hyphenated domain structure ({hyphen_count} hyphens)")
    elif hyphen_count == 1:
        # Only flag single-hyphen if combined with a brand or suspicious TLD
        if any(brand in domain for brand in TRUSTED_BRANDS) or suffix in SUSPICIOUS_TLDS:
            risk += 10
            flags.append("Hyphenated domain combined with brand/suspicious TLD")

    # 4. Abnormally long domain
    if len(domain) > 25:
        risk += 10
        flags.append(f"Unusually long domain ({len(domain)} chars)")

    return {"url_risk": risk, "url_flags": flags}

# =============================================================================
# ─── Keyword Detection Helper ────────────────────────────────────────────────
# =============================================================================

def detect_keywords(text: str) -> dict:
    """
    Scan text against all SCAM_PATTERNS.

    Returns matched_categories and matched_keywords (both deduplicated).
    """
    lowered  = text.lower()
    cats: List[str] = []
    kws:  List[str] = []

    for category, keywords in SCAM_PATTERNS.items():
        for kw in keywords:
            if kw in lowered:
                if category not in cats:
                    cats.append(category)
                if kw not in kws:
                    kws.append(kw)

    return {"matched_categories": cats, "matched_keywords": kws}

# =============================================================================
# ─── Core Detection Function ─────────────────────────────────────────────────
# =============================================================================

def detect_phish(input_data: str) -> dict:
    """
    Multi-signal scam detection pipeline.

    Layers:
        L0  URL extraction + parsing
        L1  Keyword matching → base score
        L2  Combo boosts
        L3  Linguistic signals
        L4  Safe-pattern defence (score reduction)
        L5  URL intelligence
        ──  Threshold decision + output assembly

    Args:
        input_data: Raw text or URL string.

    Returns:
        Complete risk assessment dict.
    """
    lowered = input_data.lower()

    # ── L0: URLs ──────────────────────────────────────────────────────────────
    detected_urls = extract_urls(input_data)
    url_analysis  = [parse_url(u) for u in detected_urls]

    # ── L1: Keywords ─────────────────────────────────────────────────────────
    kw_result          = detect_keywords(input_data)
    matched_categories = kw_result["matched_categories"]
    matched_keywords   = kw_result["matched_keywords"]

    base_score = sum(SCAM_WEIGHTS.get(c, 10) for c in matched_categories)

    # ── L2: Combo boosts ──────────────────────────────────────────────────────
    combo_boost, combo_labels = apply_combo_boosts(set(matched_categories), lowered)

    # ── L3: Linguistic signals ────────────────────────────────────────────────
    ling_boost, ling_signals = detect_linguistic_signals(input_data)

    # ── L4: Safe patterns ─────────────────────────────────────────────────────
    safe_reduction, safe_signals = detect_safe_signals(input_data)

    # ── L5: URL intelligence ──────────────────────────────────────────────────
    url_risk_total = 0
    url_risk_flags: List[str] = []

    for url_info in url_analysis:
        result = analyze_url_risk(url_info)
        url_risk_total += result["url_risk"]
        url_risk_flags.extend(result["url_flags"])

    # ── Score assembly ────────────────────────────────────────────────────────
    raw_score  = base_score + combo_boost + ling_boost + url_risk_total + safe_reduction
    risk_score = max(0, min(100, raw_score))  # clamp [0, 100]

    # ── Confidence: one signal = 10 pts, capped at 100 ───────────────────────
    total_signals = (
        len(matched_categories)
        + len(combo_labels)
        + len(ling_signals)
        + len(url_risk_flags)
        - len(safe_signals)            # safe patterns reduce confidence too
    )
    confidence_score = min(100, max(0, total_signals * 10))

    # ── Threshold decision ────────────────────────────────────────────────────
    if risk_score >= 70:
        status   = "scam"
        is_scam  = True
        impact   = "High risk of financial loss or identity theft."
        action   = "Do NOT click any links or share any information. Block the sender."
    elif risk_score >= 40:
        status   = "suspicious"
        is_scam  = False
        impact   = "Potentially harmful — treat with caution."
        action   = "Do not share personal information. Verify through official channels."
    else:
        status   = "safe"
        is_scam  = False
        impact   = "No significant threat detected."
        action   = "No action required."

    # ── Category labels ───────────────────────────────────────────────────────
    primary_category = (
        max(matched_categories, key=lambda c: SCAM_WEIGHTS.get(c, 0))
        if matched_categories else ("url_scam" if url_risk_flags else "safe")
    )
    secondary_categories = [c for c in matched_categories if c != primary_category]

    # ── Red flags (unified) ───────────────────────────────────────────────────
    red_flags: List[str] = []

    for cat in matched_categories:
        label = CATEGORY_FLAG_LABELS.get(cat)
        if label and label not in red_flags:
            red_flags.append(label)

    for label in combo_labels + ling_signals + url_risk_flags:
        if label not in red_flags:
            red_flags.append(label)

    # ── Explanation markdown ──────────────────────────────────────────────────
    status_icon  = {"scam": "🚨", "suspicious": "🔶", "safe": "✅"}[status]
    cat_list     = ", ".join(matched_categories)  if matched_categories  else "None"
    kw_list      = ", ".join(matched_keywords)    if matched_keywords    else "None"
    flag_block   = "\n".join(f"- {f}" for f in red_flags) if red_flags else "- None"

    explanation  = f"""### PhishGuard Analysis Report

**Status:** {status_icon} {status.upper()}  
**Risk Score:** {risk_score}/100  
**Confidence:** {confidence_score}%  
**Primary Category:** {primary_category.replace("_", " ").title()}  
**All Detected Categories:** {cat_list}  

---

### 🔍 Signals Triggered
{flag_block}

**Matched keywords:** {kw_list}  
**URLs analysed:** {len(detected_urls)}  
"""

    if combo_labels:
        explanation += "\n### ⚡ High-Risk Combinations\n"
        explanation += "\n".join(f"- {l}" for l in combo_labels) + "\n"

    if url_risk_flags:
        explanation += "\n### 🌐 URL Risk Signals\n"
        explanation += "\n".join(f"- {f}" for f in url_risk_flags) + "\n"

    if safe_signals:
        explanation += "\n### 🛡️ Safe Signals Detected (Score Reduced)\n"
        explanation += "\n".join(f"- '{s}'" for s in safe_signals) + "\n"

    explanation += f"""
---

### 📋 Recommendation
**{action}**

*Impact assessment: {impact}*"""

    # ── Final response ─────────────────────────────────────────────────────────
    return {
        # ── Core (backward compatible) ────────────────────────────────────────
        "is_scam":              is_scam,
        "risk_score":           risk_score,
        "category":             primary_category,   # alias kept for compatibility
        "red_flags":            red_flags,
        "impact":               impact,
        "action":               action,
        "explanation_markdown": explanation,
        "detected_urls":        detected_urls,
        "url_analysis":         url_analysis,
        "matched_categories":   matched_categories,
        "matched_keywords":     matched_keywords,
        # ── New v2 fields ─────────────────────────────────────────────────────
        "status":               status,
        "primary_category":     primary_category,
        "secondary_categories": secondary_categories,
        "confidence_score":     confidence_score,
        "url_risk_flags":       url_risk_flags,
        "safe_signals_detected": safe_signals,
    }

# =============================================================================
# Input Pre-Processor
# =============================================================================

# Unicode ranges used for language detection
_DEVANAGARI_RE = re.compile(r'[\u0900-\u097F]')   # Hindi + Marathi script
_MARATHI_WORDS  = {"आहे", "नाही", "करा", "आपण", "हे", "ते", "करू", "नका", "वाटते", "असे"}
_HINDI_WORDS    = {"है", "हैं", "नहीं", "करें", "आपका", "आपकी", "यह", "वह", "तुरंत", "जाएगा"}


def detect_language(text: str) -> str:
    """
    Detect whether text is English, Hindi, or Marathi.

    Strategy:
      1. If no Devanagari script → English ("en")
      2. If Devanagari present, check for known Marathi marker words → "mr"
      3. Otherwise assume Hindi → "hi"

    Returns one of: "en", "hi", "mr"
    """
    if not _DEVANAGARI_RE.search(text):
        return "en"

    words = set(text.split())
    if words & _MARATHI_WORDS:
        return "mr"

    return "hi"


def prepare_input(raw: str) -> dict:
    """
    Convert any raw user input string into the strict JSON structure
    required by detect_phish() and the /detect API endpoint.

    Handles:
      - Plain English / Hindi / Marathi messages
      - Bare URLs (text = url = the URL itself)
      - Mixed messages containing embedded URLs
      - Auto language detection (en / hi / mr)

    Args:
        raw: Any free-form string from the user.

    Returns:
        {
            "text":     str,   # cleaned message (always populated)
            "url":      str,   # first URL found, or "" if none
            "language": str,   # "en" | "hi" | "mr"
        }

    Example:
        >>> prepare_input("Click here: https://paytm-secure-login.xyz")
        {"text": "Click here: https://paytm-secure-login.xyz",
         "url": "https://paytm-secure-login.xyz", "language": "en"}

        >>> prepare_input("आपका बैंक खाता बंद हो जाएगा")
        {"text": "आपका बैंक खाता बंद हो जाएगा", "url": "", "language": "hi"}
    """
    # Normalise whitespace
    text = " ".join(raw.strip().split())

    # Extract first URL (if any)
    urls = extract_urls(text)
    url  = urls[0] if urls else ""

    # Detect language
    language = detect_language(text)

    return {
        "text":     text,
        "url":      url,
        "language": language,
    }


# =============================================================================
# API Routes
# =============================================================================

@app.get("/health", summary="Health check")
def health_check():
    """Returns service liveness status."""
    return {"status": "ok", "version": "2.0.0"}


@app.post("/analyze", summary="Raw text → auto-parse → detect (no manual JSON needed)")
def analyze(payload: dict):
    """
    Accepts a simple { "input": "<raw message or url>" } body.

    Internally calls prepare_input() to build the structured request,
    then runs the full detection pipeline. No manual JSON formatting needed.

    Example body:
        { "input": "Your account is blocked. Update KYC immediately." }
        { "input": "आपका बैंक खाता बंद कर दिया जाएगा" }
        { "input": "https://paytm-secure-login.xyz" }
    """
    raw = payload.get("input", "").strip()
    if not raw:
        raise HTTPException(status_code=422, detail="Field 'input' is required and cannot be empty.")

    structured = prepare_input(raw)
    lang       = structured["language"]
    template   = LANGUAGE_TEMPLATES.get(lang, LANGUAGE_TEMPLATES["en"])

    result = detect_phish(structured["text"])

    status = result["status"]
    result["user_message"]    = template.get(status, template["safe"])
    result["user_action"]     = template["action"]
    result["parsed_input"]    = structured   # shows what was auto-detected

    return result


@app.post("/detect", summary="Analyse text or URL for phishing/scam signals")
def detect(request: DetectRequest):
    """
    Multi-signal scam analysis.

    Body: { "text": "...", "url": "...", "language": "en|hi|mr" }
    At least one of text / url is required.
    """
    if not request.text and not request.url:
        raise HTTPException(
            status_code=422,
            detail="Request must include at least one of: 'text', 'url'",
        )

    input_data = request.text if request.text else request.url
    lang       = request.language if request.language in LANGUAGE_TEMPLATES else "en"
    template   = LANGUAGE_TEMPLATES[lang]

    result = detect_phish(input_data)

    status = result["status"]
    result["user_message"] = template.get(status, template["safe"])
    result["user_action"]  = template["action"]

    return result

# =============================================================================
# CLI
# =============================================================================

def run_cli():
    """
    Interactive CLI — just paste any raw message or URL.
    prepare_input() handles all formatting automatically.
    """
    print("=" * 55)
    print("  PhishGuard v2.0 — Multi-Signal Scam Detection CLI")
    print("=" * 55)
    print("Paste any message or URL — no formatting needed.")
    print("Language is detected automatically. (Ctrl+C to quit)\n")

    try:
        user_input = input("Input : ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return

    if not user_input:
        print("No input provided. Exiting.")
        return

    # ── Auto-format the raw input ─────────────────────────────────────────────
    structured = prepare_input(user_input)
    lang       = structured["language"]
    template   = LANGUAGE_TEMPLATES.get(lang, LANGUAGE_TEMPLATES["en"])

    print(f"\n── Auto-detected input structure ──")
    print(json.dumps(structured, indent=2, ensure_ascii=False))
    print()

    # ── Run detection ─────────────────────────────────────────────────────────
    result = detect_phish(structured["text"])

    status = result["status"]
    result["user_message"] = template.get(status, template["safe"])
    result["user_action"]  = template["action"]
    result["parsed_input"] = structured

    print(f"{result['user_message']}")
    print(f"Risk Score : {result['risk_score']}/100  |  Confidence : {result['confidence_score']}%")
    print(f"Status     : {status.upper()}  |  Category : {result['primary_category']}")
    print(f"👉 {result['user_action']}\n")
    print("─── Full Result ───")
    print(json.dumps(result, indent=2, ensure_ascii=False))

# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    if "--serve" in sys.argv:
        # Pass app object directly — avoids Windows module-not-found error.
        # reload=True requires uvicorn CLI and breaks on Windows path imports.
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        run_cli()
