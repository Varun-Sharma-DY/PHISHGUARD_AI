"""
PhishGuard v2.0 — Multi-Signal Scoring Engine + Translation Layer
=================================================================
Architecture:
  INPUT  → Normalize to English (if non-English detected)
         → Detection runs on English text (rules + LLM)
         → Translate user-facing output to selected language
  OUTPUT → user_message + user_action in user's language
           everything else stays English

Signal Layers:
  L0 — URL extraction & parsing
  L1 — Keyword matching       (per-category weighted scores)
  L2 — Combo boost logic      (dangerous category combinations)
  L3 — Linguistic signals     (imperative tone, urgency phrases)
  L4 — Safe-pattern defence   (negation / awareness phrases)
  L5 — URL intelligence       (TLD abuse, brand impersonation,
                                shortener detection)
  L6 — LLM second opinion     (fires on all scores < 61,
                                can escalate safe → suspicious)
  L7 — Translation layer      (user_message + user_action only)

Scoring thresholds:
  >= 70  → scam
  >= 40  → suspicious
  <  40  → safe
"""
import requests
import os
import re
import json
import sys
import uvicorn
import tldextract
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from dotenv import load_dotenv
load_dotenv()

# =============================================================================
# App
# =============================================================================

app = FastAPI(
    title="PhishGuard API",
    description="Multi-signal phishing & scam detection engine with translation",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Language Map — 29 languages via LLM translation
# =============================================================================

LANGUAGE_MAP = {
    "en":  "English",
    "hi":  "Hindi",
    "mr":  "Marathi",
    "bn":  "Bengali",
    "te":  "Telugu",
    "ta":  "Tamil",
    "gu":  "Gujarati",
    "kn":  "Kannada",
    "ml":  "Malayalam",
    "pa":  "Punjabi",
    "or":  "Odia",
    "as":  "Assamese",
    "ur":  "Urdu",
    "sa":  "Sanskrit",
    "kok": "Konkani",
    "mni": "Manipuri",
    "ne":  "Nepali",
    "mai": "Maithili",
    "sd":  "Sindhi",
    "sat": "Santali",
    "brx": "Bodo",
    "doi": "Dogri",
    "raj": "Rajasthani",
    "bho": "Bhojpuri",
    "ks":  "Kashmiri",
    "hne": "Chhattisgarhi",
    "bgc": "Haryanvi",
    "kha": "Khasi",
    "lus": "Mizo",
}

# =============================================================================
# Request Schema
# =============================================================================

class DetectRequest(BaseModel):
    text:     Optional[str] = None
    url:      Optional[str] = None
    language: Optional[str] = "en"

# =============================================================================
# ─── INPUT NORMALIZATION ─────────────────────────────────────────────────────
# =============================================================================

def is_predominantly_non_english(text: str) -> bool:
    """
    Returns True if the text is likely non-English script
    (Devanagari, Malayalam, Tamil, Telugu, Bengali, Gujarati, etc.)

    Strategy: count characters outside basic ASCII + Latin extended range.
    If more than 25% of alphabetic characters are non-Latin, treat as
    non-English and translate before detection.
    """
    alpha_chars = [c for c in text if c.isalpha()]
    if not alpha_chars:
        return False
    non_latin = sum(1 for c in alpha_chars if ord(c) > 0x024F)
    return (non_latin / len(alpha_chars)) > 0.25


def normalize_to_english(text: str) -> str:
    """
    Translate non-English input to English before running detection.

    - URLs are explicitly preserved so rule engine can still analyze them.
    - Original text is kept for output/translation back to user's language.
    - On failure, returns original text (detection degrades gracefully).

    This is called ONLY when is_predominantly_non_english() returns True.
    """
    api_url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
        "Content-Type": "application/json"
    }

    prompt = f"""Translate the following text to English.

Important rules:
- Preserve ALL URLs exactly as they appear — do not change them
- Preserve numbers, amounts (₹, $), and phone numbers exactly
- Return ONLY the translated English text
- No explanation, no quotes, no extra text

Text:
{text}"""

    data = {
        "model": "deepseek/deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1
    }

    try:
        res     = requests.post(api_url, headers=headers, json=data, timeout=10)
        content = res.json()["choices"][0]["message"]["content"].strip()
        print(f"[Normalization] Translated input: {content[:120]}...")
        return content
    except Exception as e:
        print(f"[Normalization] Failed, using original: {e}")
        return text  # Graceful fallback — detection still runs on original


# =============================================================================
# ─── OUTPUT TRANSLATION LAYER (L7) ───────────────────────────────────────────
# =============================================================================

def translate_text(text: str, target_lang_code: str) -> str:
    """
    Translate English output text to the user's selected language.

    Called AFTER all detection is complete.
    Only translates: user_message, user_action.
    Never translates: risk_score, categories, red_flags, explanation_markdown.
    """
    target_lang = LANGUAGE_MAP.get(target_lang_code, "English")

    api_url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
        "Content-Type": "application/json"
    }

    prompt = f"""Translate the following text into {target_lang}.

Keep it:
- simple and clear
- suitable for common Indian users who may not be tech-savvy
- natural sounding, not robotic

Return ONLY the translated text. No explanation, no quotes, no extra text.

Text:
{text}"""

    data = {
        "model": "deepseek/deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        res     = requests.post(api_url, headers=headers, json=data, timeout=10)
        content = res.json()["choices"][0]["message"]["content"]
        return content.strip()
    except Exception as e:
        print(f"[Translation] Error ({target_lang_code}): {e}")
        return text  # Graceful fallback — return English


# =============================================================================
# ─── LLM SECOND OPINION (L6) ─────────────────────────────────────────────────
# =============================================================================

def analyze_with_llm(text: str, rule_score: int) -> dict:
    """
    LLM second opinion on borderline messages.
    Always receives English text (normalized if needed).
    Fires on all scores < 61.

    Can escalate safe → suspicious.
    Never downgrades scam verdicts.
    Never changes risk_score or scored fields.
    """
    api_url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
        "Content-Type": "application/json"
    }

    prompt = f"""You are a cybersecurity expert specializing in scam detection for Indian users.

A rule-based system analysed the following message and gave it a risk score of {rule_score}/100.
A score below 40 means the rules consider it safe. Your job is to act as a second opinion.

Carefully check for these scam patterns that rules often miss:
- URL shorteners (bit.ly, tinyurl, etc.) hiding real phishing destinations
- Fake urgency: "pay now", "avoid disconnection", "expires today"
- Impersonation of banks, government, electricity boards, job portals, UPI
- Requests to click a link and enter personal or financial details
- Too-good-to-be-true offers: jobs, refunds, prizes
- Subscription renewal or utility bill scams

Message to analyse:
{text}

Return ONLY valid JSON. No text outside the JSON block.
{{
  "llm_verdict": "safe | suspicious | scam",
  "explanation": "2-3 sentences explaining your reasoning in plain English.",
  "user_message": "One clear sentence verdict for a non-technical user.",
  "action": "One sentence telling the user exactly what to do."
}}"""

    data = {
        "model": "deepseek/deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }

    try:
        response = requests.post(api_url, headers=headers, json=data, timeout=12)
        result   = response.json()
        content  = result["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = re.sub(r"^```[a-z]*\n?", "", content)
            content = re.sub(r"\n?```$", "", content.strip())
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None
        if parsed.get("llm_verdict") not in ("safe", "suspicious", "scam"):
            parsed["llm_verdict"] = "suspicious"
        return parsed
    except Exception as e:
        print(f"[LLM] Error: {e}")
        return None


# =============================================================================
# ─── SIGNAL LAYER 0: URL Helpers ─────────────────────────────────────────────
# =============================================================================

_URL_RE = re.compile(
    r"https?://(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    text = text.strip()
    if re.match(r"^https?://\S+$", text, re.IGNORECASE):
        return [text]
    return _URL_RE.findall(text)


def parse_url(url: str) -> dict:
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
        "upi id", "verify your upi",
        "पेमेंट रिक्वेस्ट", "यूपीआई पिन", "पैसे वापस करें", "गलती से ट्रांसफर",
    ],
    "otp_scam": [
        "share otp", "enter otp", "verification code",
        "transaction otp", "bank otp", "otp for verification",
        "ओटीपी शेयर करें", "ओटीपी दर्ज करें", "ओटीपी बताएं", "वेरिफिकेशन कोड",
    ],
    "bank_scam": [
        "account blocked", "account suspended",
        "kyc expired", "update kyc",
        "reactivate account", "verify account", "verify your account",
        "unblock account", "suspicious activity",
        "requires verification", "update your details",
        "confirm your details", "verify your details",
        "avoid restriction", "avoid temporary",
        "recent activity", "unusual activity",
        "temporary restriction", "access restricted",
        "re-verify", "re-confirm",
        "खाता बंद", "केवाईसी अपडेट", "kyc अपडेट", "बैंक खाता बंद",
        "अकाउंट ब्लॉक", "खाता निलंबित",
    ],
    "urgency": [
        "urgent", "immediately", "action required",
        "within 24 hours", "act now", "last chance",
        "expires soon", "avoid penalty",
        "pay immediately", "avoid disconnection",
        "will be interrupted", "interrupted today",
        "without interruption", "service will be",
        "तुरंत", "अभी करें", "जल्दी करें", "अंतिम मौका",
        "24 घंटे में", "अभी क्लिक करें",
    ],
    "prize_scam": [
        "you have won", "you won", "won a prize", "won ₹",
        "cash prize", "lucky draw", "lucky winner",
        "claim your prize", "claim prize", "claim now",
        "reward money", "processing fee",
        "shortlisted", "been selected", "you have been shortlisted",
        "आपने जीता", "₹5000 जीता", "इनाम जीता", "लकी ड्रा",
        "पुरस्कार जीता", "अभी क्लेम करें", "नकद पुरस्कार",
    ],
    "tax_scam": [
        "income tax refund", "refund pending",
        "pan blocked", "link aadhaar",
        "verify pan", "tax department", "claim refund",
        "pending refund", "received a pending refund",
        "आयकर रिफंड", "पैन ब्लॉक", "आधार लिंक", "रिफंड लंबित",
    ],
    "delivery_scam": [
        "delivery failed", "parcel held", "address issue",
        "reschedule delivery", "redelivery", "confirm delivery", "delivery otp",
        "डिलीवरी फेल", "पार्सल रोका", "पता सही करें",
    ],
    "loan_scam": [
        "instant loan", "loan approved", "loan in 5 minutes",
        "no credit check", "instant approval", "loan offer", "processing fee",
        "तुरंत लोन", "लोन अप्रूव", "5 मिनट में लोन",
    ],
    "digital_arrest_scam": [
        "digital arrest", "arrest warrant", "case registered",
        "under investigation", "illegal parcel", "money laundering",
        "freeze account", "police case", "video call now", "prove innocence",
        "डिजिटल अरेस्ट", "गिरफ्तारी वारंट", "मनी लॉन्ड्रिंग",
        "पुलिस केस", "निर्दोषिता साबित",
    ],
    "challan_scam": [
        "pending challan", "traffic violation", "pay fine",
        "license suspended", "unpaid fine", "vehicle violation", "e-challan link",
        "unpaid dues", "unpaid bill",
        "चालान", "ई-चालान", "जुर्माना भरें", "लाइसेंस निलंबित",
    ],
    "scheme_scam": [
        "pm kisan", "pension benefit", "government scheme", "subsidy",
        "bonus payment", "extra payment", "verify aadhaar",
        "सरकारी योजना", "सब्सिडी", "आधार वेरिफाई", "पेंशन लाभ", "पीएम किसान",
    ],
    "family_emergency_scam": [
        "road accident", "hospitalised", "medical emergency",
        "need urgent help", "send money urgently", "in hospital",
        "सड़क दुर्घटना", "अस्पताल में", "मेडिकल इमरजेंसी", "तुरंत पैसे भेजें",
    ],
    "scholarship_scam": [
        "scholarship", "education grant", "student benefit", "claim scholarship",
        "छात्रवृत्ति", "शिक्षा अनुदान",
    ],
    "job_scam": [
        "part-time job", "work from home", "remote job", "earn from home",
        "daily payment", "weekly payment", "confirm your slot",
        "filling details", "job confirm", "job offer",
        "घर से काम", "पार्ट टाइम जॉब",
    ],
    "utility_scam": [
        "electricity bill", "electricity service", "power supply",
        "disconnection", "bill overdue", "outstanding bill",
        "gas connection", "water supply",
        "बिजली बिल", "बिजली कनेक्शन", "कनेक्शन काटा जाएगा",
    ],
    "subscription_scam": [
        "subscription", "subscription expired", "subscription is about to expire",
        "renew now", "renew your plan", "continue services",
        "plan expired", "membership expired",
    ],
}

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
    "job_scam":              20,
    "utility_scam":          20,
    "subscription_scam":     15,
}

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
    "job_scam":              "Fake job or work-from-home offer",
    "utility_scam":          "Threatens utility disconnection",
    "subscription_scam":     "Fake subscription renewal pressure",
}

# =============================================================================
# ─── SIGNAL LAYER 2: Combo Boosts ────────────────────────────────────────────
# =============================================================================

COMBO_BOOSTS = [
    ({"bank_scam", "urgency"},           None,      20, "Bank threat + urgency combined"),
    ({"upi_scam"},                       "approve", 25, "UPI approve request — classic scam pattern"),
    ({"prize_scam"},                     "fee",     20, "Prize + fee demand — advance fee scam"),
    ({"prize_scam", "urgency"},          None,      25, "Prize claim + urgency — pressure scam"),
    ({"otp_scam", "bank_scam"},          None,      15, "OTP + bank threat — credential phishing"),
    ({"digital_arrest_scam", "urgency"}, None,      20, "Digital arrest + urgency — high-pressure scam"),
    ({"utility_scam", "urgency"},        None,      20, "Utility threat + urgency — disconnection scam"),
    ({"job_scam", "prize_scam"},         None,      15, "Job offer + prize language — classic job scam"),
    ({"tax_scam", "upi_scam"},           None,      20, "Refund + UPI — refund phishing scam"),
    ({"subscription_scam", "urgency"},   None,      15, "Subscription expiry + urgency — renewal scam"),
]


def apply_combo_boosts(categories: set, lowered_text: str) -> tuple[int, List[str]]:
    boost  = 0
    labels = []
    for required_cats, keyword, points, label in COMBO_BOOSTS:
        if not required_cats.issubset(categories):
            continue
        if keyword and keyword not in lowered_text:
            continue
        boost  += points
        labels.append(label)
    return boost, labels

# =============================================================================
# ─── SIGNAL LAYER 3: Linguistic Signals ──────────────────────────────────────
# =============================================================================

_IMPERATIVE_PATTERNS = re.compile(
    r"\b(click|call|send|pay|share|verify|confirm|update|submit|approve|transfer|download|renew|fill)\b",
    re.IGNORECASE,
)

_URGENCY_PHRASES = [
    "do not ignore", "failure to", "or else", "otherwise",
    "legal action", "consequences", "penalty", "blocked",
    "will be disconnected", "will be suspended", "will be interrupted",
]


def detect_linguistic_signals(text: str) -> tuple[int, List[str]]:
    boost   = 0
    signals = []
    lowered = text.lower()

    imperatives        = _IMPERATIVE_PATTERNS.findall(text)
    unique_imperatives = list({v.lower() for v in imperatives})
    if len(unique_imperatives) >= 2:
        boost += 10
        signals.append(f"Multiple imperative verbs detected: {', '.join(unique_imperatives[:4])}")

    for phrase in _URGENCY_PHRASES:
        if phrase in lowered:
            boost += 5
            signals.append(f"Urgency amplifier: '{phrase}'")
            break

    return boost, signals

# =============================================================================
# ─── SIGNAL LAYER 4: Safe Patterns ───────────────────────────────────────────
# =============================================================================

SAFE_PATTERNS = [
    "do not share otp", "never share your otp",
    "bank will never ask", "never share your pin",
    "do not share your pin", "beware of fraud",
    "this is a scam", "report fraud",
    "protect yourself", "stay safe from",
    "ओटीपी किसी से साझा न करें",
    "बैंक कभी नहीं मांगता",
    "धोखाधड़ी से सावधान",
]

_SAFE_PATTERN_PENALTY = -30


def detect_safe_signals(text: str) -> tuple[int, List[str]]:
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

_OFFICIAL_DOMAINS = {
    "google", "amazon", "flipkart", "sbi", "hdfcbank",
    "icicibank", "axisbank", "paytm", "phonepe",
}

_URL_SHORTENERS = {
    "bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly",
    "short.io", "rebrand.ly", "cutt.ly", "is.gd", "buff.ly",
    "tiny.cc", "bl.ink", "rb.gy", "shorte.st", "clck.ru",
}


def analyze_url_risk(url_info: dict) -> dict:
    risk        = 0
    flags       = []
    domain      = url_info["domain"].lower()
    suffix      = url_info["suffix"].lower()
    full_domain = f"{domain}.{suffix}"

    if domain in _OFFICIAL_DOMAINS:
        return {"url_risk": 0, "url_flags": []}

    if suffix in SUSPICIOUS_TLDS:
        risk += 25
        flags.append(f"Suspicious domain extension: .{suffix}")

    for brand in TRUSTED_BRANDS:
        if brand in domain and domain != brand:
            risk += 30
            flags.append(f"Possible brand impersonation: '{brand}' in domain")
            break

    hyphen_count = domain.count("-")
    if hyphen_count >= 2:
        risk += 15
        flags.append(f"Heavily hyphenated domain structure ({hyphen_count} hyphens)")
    elif hyphen_count == 1:
        if any(brand in domain for brand in TRUSTED_BRANDS) or suffix in SUSPICIOUS_TLDS:
            risk += 10
            flags.append("Hyphenated domain combined with brand/suspicious TLD")

    if len(domain) > 25:
        risk += 10
        flags.append(f"Unusually long domain ({len(domain)} chars)")

    if domain in _URL_SHORTENERS or full_domain in _URL_SHORTENERS:
        risk += 20
        flags.append(f"URL shortener detected ({full_domain}) — real destination is hidden")

    return {"url_risk": risk, "url_flags": flags}

# =============================================================================
# ─── Keyword Detection Helper ────────────────────────────────────────────────
# =============================================================================

def detect_keywords(text: str) -> dict:
    lowered = text.lower()
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

def detect_phish(input_data: str, language: str = "en") -> dict:
    """
    Full detection pipeline.

    Step 1 — Normalize: if input is non-English, translate to English first.
              URLs are preserved. Original text kept for output.
    Step 2 — Detect: all layers run on English text.
    Step 3 — LLM: second opinion on borderline scores (< 61).
    Step 4 — Translate: user_message + user_action → user's language.

    Args:
        input_data: Raw text or URL from user (any language).
        language:   Output language code. Default "en".
    """

    # ── Step 1: Input Normalization ───────────────────────────────────────────
    # Always extract URLs from the ORIGINAL input — they must not be altered.
    # Run all detection on the English-normalized version of the text.
    detected_urls = extract_urls(input_data)  # from original, always

    if is_predominantly_non_english(input_data):
        print(f"[Normalization] Non-English input detected, translating to English...")
        detection_text = normalize_to_english(input_data)
    else:
        detection_text = input_data

    lowered = detection_text.lower()

    # ── L0: URL analysis (on original URLs) ──────────────────────────────────
    url_analysis = [parse_url(u) for u in detected_urls]

    # ── L1: Keywords (on normalized English text) ─────────────────────────────
    kw_result          = detect_keywords(detection_text)
    matched_categories = kw_result["matched_categories"]
    matched_keywords   = kw_result["matched_keywords"]
    base_score         = sum(SCAM_WEIGHTS.get(c, 10) for c in matched_categories)

    # ── L2: Combo boosts ──────────────────────────────────────────────────────
    combo_boost, combo_labels = apply_combo_boosts(set(matched_categories), lowered)

    # ── L3: Linguistic signals ────────────────────────────────────────────────
    ling_boost, ling_signals = detect_linguistic_signals(detection_text)

    # ── L4: Safe patterns ─────────────────────────────────────────────────────
    safe_reduction, safe_signals = detect_safe_signals(detection_text)

    # ── L5: URL intelligence ──────────────────────────────────────────────────
    url_risk_total = 0
    url_risk_flags: List[str] = []

    for url_info in url_analysis:
        result = analyze_url_risk(url_info)
        url_risk_total += result["url_risk"]
        url_risk_flags.extend(result["url_flags"])

    # ── Score assembly ────────────────────────────────────────────────────────
    raw_score  = base_score + combo_boost + ling_boost + url_risk_total + safe_reduction
    risk_score = max(0, min(100, raw_score))

    # ── Confidence ────────────────────────────────────────────────────────────
    total_signals    = (
        len(matched_categories) + len(combo_labels)
        + len(ling_signals) + len(url_risk_flags)
        - len(safe_signals)
    )
    confidence_score = min(100, max(0, total_signals * 10))

    # ── Rule engine threshold decision ───────────────────────────────────────
    if risk_score >= 70:
        status       = "scam"
        is_scam      = True
        impact       = "High risk of financial loss or identity theft."
        action       = "Do NOT click any links or share any information. Block the sender."
        user_message = "⚠️ This appears to be a scam."
    elif risk_score >= 40:
        status       = "suspicious"
        is_scam      = False
        impact       = "Potentially harmful — treat with caution."
        action       = "Do not share personal information. Verify through official channels."
        user_message = "🔶 This message looks suspicious."
    else:
        status       = "safe"
        is_scam      = False
        impact       = "No significant threat detected."
        action       = "No action required."
        user_message = "✅ This looks safe."

    # ── Category labels ───────────────────────────────────────────────────────
    primary_category = (
        max(matched_categories, key=lambda c: SCAM_WEIGHTS.get(c, 0))
        if matched_categories else ("url_scam" if url_risk_flags else "safe")
    )
    secondary_categories = [c for c in matched_categories if c != primary_category]

    # ── Red flags ─────────────────────────────────────────────────────────────
    red_flags: List[str] = []
    for cat in matched_categories:
        label = CATEGORY_FLAG_LABELS.get(cat)
        if label and label not in red_flags:
            red_flags.append(label)
    for label in combo_labels + ling_signals + url_risk_flags:
        if label not in red_flags:
            red_flags.append(label)

    # ── Explanation markdown ──────────────────────────────────────────────────
    status_icon = {"scam": "🚨", "suspicious": "🔶", "safe": "✅"}[status]
    cat_list    = ", ".join(matched_categories) if matched_categories else "None"
    kw_list     = ", ".join(matched_keywords)   if matched_keywords   else "None"
    flag_block  = "\n".join(f"- {f}" for f in red_flags) if red_flags else "- None"

    explanation = f"""### PhishGuard Analysis Report

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

    # ── Build final response ──────────────────────────────────────────────────
    final_result = {
        # Core detection fields — never translated
        "is_scam":               is_scam,
        "risk_score":            risk_score,
        "category":              primary_category,
        "red_flags":             red_flags,
        "impact":                impact,
        "action":                action,
        "explanation_markdown":  explanation,
        "detected_urls":         detected_urls,
        "url_analysis":          url_analysis,
        "matched_categories":    matched_categories,
        "matched_keywords":      matched_keywords,
        "status":                status,
        "primary_category":      primary_category,
        "secondary_categories":  secondary_categories,
        "confidence_score":      confidence_score,
        "url_risk_flags":        url_risk_flags,
        "safe_signals_detected": safe_signals,
        # User-facing fields (translated in L7 if needed)
        "user_message":          user_message,
        "user_action":           action,
    }

    # ── L6: LLM Second Opinion ────────────────────────────────────────────────
    # Always receives English text (normalized if input was non-English).
    # Fires on all scores < 61. Can escalate safe → suspicious.
    if risk_score < 61:
        llm_result = analyze_with_llm(detection_text, risk_score)

        if llm_result:
            llm_verdict = llm_result.get("llm_verdict", "safe")

            if status == "safe" and llm_verdict in ("suspicious", "scam"):
                final_result["status"]  = "suspicious"
                final_result["is_scam"] = False
                final_result["impact"]  = "Potentially harmful — treat with caution."
                final_result["red_flags"].append(
                    "⚠️ AI analysis flagged this as suspicious despite low rule score"
                )
                final_result["user_message"] = "🔶 This message looks suspicious."

            if "explanation" in llm_result:
                final_result["explanation_markdown"] = llm_result["explanation"]
            if "user_message" in llm_result:
                final_result["user_message"] = llm_result["user_message"]
            if "action" in llm_result:
                final_result["action"]      = llm_result["action"]
                final_result["user_action"] = llm_result["action"]

    # ── L7: Output Translation ────────────────────────────────────────────────
    # Runs last, after all detection is finalized.
    # Translates ONLY user_message and user_action.
    if language != "en" and language in LANGUAGE_MAP:
        final_result["user_message"] = translate_text(
            final_result["user_message"], language
        )
        final_result["user_action"] = translate_text(
            final_result["user_action"], language
        )

    return final_result

# =============================================================================
# API Routes
# =============================================================================

@app.get("/health", summary="Health check")
def health_check():
    return {
        "status": "ok",
        "version": "2.0.0",
        "supported_languages": len(LANGUAGE_MAP),
    }


@app.post("/detect", summary="Analyse text or URL for phishing/scam signals")
def detect(request: DetectRequest):
    """
    Multi-signal scam analysis with auto language normalization + translation.

    Body: { "text": "...", "url": "...", "language": "en|hi|ml|ta|..." }
    - text/url: at least one required (any language)
    - language: output language code (default "en")

    Non-English input is automatically translated to English for detection,
    then the verdict is translated back to the user's selected language.
    """
    if not request.text and not request.url:
        raise HTTPException(
            status_code=422,
            detail="Request must include at least one of: 'text', 'url'",
        )

    input_data = request.text if request.text else request.url
    language   = request.language if request.language in LANGUAGE_MAP else "en"

    result = detect_phish(input_data, language)
    return result

# =============================================================================
# CLI
# =============================================================================

def run_cli():
    print("=" * 55)
    print("  PhishGuard v2.0 — Multi-Signal Scam Detection CLI")
    print("=" * 55)
    supported = ", ".join(sorted(LANGUAGE_MAP.keys()))
    print(f"Supported language codes: {supported}\n")

    try:
        user_input = input("Input    : ").strip()
        lang_input = input("Language [default: en]: ").strip() or "en"
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return

    if not user_input:
        print("No input provided. Exiting.")
        return

    language = lang_input if lang_input in LANGUAGE_MAP else "en"
    result   = detect_phish(user_input, language)

    print(f"\n{result['user_message']}")
    print(f"Risk Score : {result['risk_score']}/100  |  Confidence : {result['confidence_score']}%")
    print(f"Status     : {result['status'].upper()}  |  Category : {result['primary_category']}")
    print(f"👉 {result['user_action']}\n")
    print("─── Full JSON ───")
    print(json.dumps(result, indent=2, ensure_ascii=False))

# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    if "--serve" in sys.argv:
        uvicorn.run("phishguard:app", host="0.0.0.0", port=8000, reload=True)
    else:
        run_cli()