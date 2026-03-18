"""
PhishGuard - Phase 6: Multilingual Support + Demo Polish
=========================================================
Extends Phase 5 with:
  - LANGUAGE_TEMPLATES : localised scam/safe messages in English, Hindi, Marathi
  - DetectRequest      : now accepts optional `language` field (default "en")
  - detect()           : resolves template, appends user_message + user_action
                         to response so end-users get plain-language warnings
                         in their preferred language
"""

import re
import json
import sys
import uvicorn
import tldextract
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

# ---------------------------------------------------------------------------
# App Initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="PhishGuard API",
    description="Phishing & scam detection service",
    version="0.6.0",
)

# ---------------------------------------------------------------------------
# Language Templates  (Phase 6)
# Plain-language verdicts for end-users — no API required, fully offline.
# Add more languages here without touching any detection logic.
# ---------------------------------------------------------------------------

LANGUAGE_TEMPLATES = {
    "en": {
        "scam": "⚠️ This appears to be a scam.",
        "safe": "✅ This looks safe.",
        "action": "Do not click any links or share sensitive information.",
    },
    "hi": {
        "scam": "⚠️ यह एक धोखाधड़ी लगती है।",
        "safe": "✅ यह सुरक्षित लगता है।",
        "action": "किसी भी लिंक पर क्लिक न करें या निजी जानकारी साझा न करें।",
    },
    "mr": {
        "scam": "⚠️ हे फसवणूक असू शकते.",
        "safe": "✅ हे सुरक्षित वाटते.",
        "action": "कोणत्याही लिंकवर क्लिक करू नका किंवा वैयक्तिक माहिती देऊ नका.",
    },
}

# ---------------------------------------------------------------------------
# Request Schema
# ---------------------------------------------------------------------------

class DetectRequest(BaseModel):
    """Accepts either a raw text snippet or a URL (at least one is required).
    Optionally specify a language code for localised user-facing messages.
    Supported: 'en' (English), 'hi' (Hindi), 'mr' (Marathi). Defaults to 'en'.
    """
    text:     Optional[str] = None
    url:      Optional[str] = None
    language: Optional[str] = "en"


# ---------------------------------------------------------------------------
# URL Helpers  (Phase 2 — unchanged)
# ---------------------------------------------------------------------------

_URL_PATTERN = re.compile(
    r"https?://"
    r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list:
    """Extract all http/https URLs from text. Returns bare URL as list if input is a URL."""
    text = text.strip()
    if re.match(r"^https?://\S+$", text, re.IGNORECASE):
        return [text]
    return _URL_PATTERN.findall(text)


def parse_url(url: str) -> dict:
    """Break a URL into domain components using tldextract."""
    extracted = tldextract.extract(url)
    return {
        "full_url":  url,
        "domain":    extracted.domain,
        "subdomain": extracted.subdomain,
        "suffix":    extracted.suffix,
    }


# ---------------------------------------------------------------------------
# Scam Pattern Dictionary  (Phase 3)
# ---------------------------------------------------------------------------

SCAM_PATTERNS = {
    "upi_scam": [
        "upi collect", "collect request", "payment request",
        "approve payment", "pay to receive",
        "wrong transfer", "mistakenly transferred",
        "return the money", "send back money",
        "share upi pin", "enter upi pin",
        # Hindi variants
        "पेमेंट रिक्वेस्ट", "यूपीआई पिन", "पैसे वापस करें",
        "गलती से ट्रांसफर",
    ],
    "otp_scam": [
        "share otp", "enter otp", "verification code",
        "transaction otp", "bank otp",
        "otp for verification",
        # Hindi variants
        "ओटीपी शेयर करें", "ओटीपी दर्ज करें", "ओटीपी बताएं",
        "वेरिफिकेशन कोड",
    ],
    "bank_scam": [
        "account blocked", "account suspended",
        "kyc expired", "update kyc",
        "reactivate account", "verify account", "verify your account",
        "unblock account", "suspicious activity",
        # Hindi variants
        "खाता बंद", "केवाईसी अपडेट", "kyc अपडेट", "बैंक खाता बंद",
        "अकाउंट ब्लॉक", "खाता निलंबित",
    ],
    "urgency": [
        "urgent", "immediately", "action required",
        "within 24 hours", "act now",
        "last chance", "expires soon",
        "avoid penalty",
        # Hindi variants
        "तुरंत", "अभी करें", "जल्दी करें", "अंतिम मौका",
        "24 घंटे में", "अभी क्लिक करें",
    ],
    "prize_scam": [
        "you have won", "you won", "won a prize", "won ₹",
        "cash prize", "lucky draw", "lucky winner",
        "claim your prize", "claim prize", "claim now",
        "reward money", "processing fee",
        # Hindi variants
        "आपने जीता", "₹5000 जीता", "इनाम जीता", "लकी ड्रा",
        "पुरस्कार जीता", "अभी क्लेम करें", "नकद पुरस्कार",
    ],
    "tax_scam": [
        "income tax refund", "refund pending",
        "pan blocked", "link aadhaar",
        "verify pan", "tax department",
        "claim refund",
        # Hindi variants
        "आयकर रिफंड", "पैन ब्लॉक", "आधार लिंक", "रिफंड लंबित",
    ],
    "delivery_scam": [
        "delivery failed", "parcel held",
        "address issue", "reschedule delivery",
        "redelivery", "confirm delivery",
        "delivery otp",
        # Hindi variants
        "डिलीवरी फेल", "पार्सल रोका", "पता सही करें",
    ],
    "loan_scam": [
        "instant loan", "loan approved",
        "loan in 5 minutes", "no credit check",
        "instant approval", "loan offer",
        "processing fee",
        # Hindi variants
        "तुरंत लोन", "लोन अप्रूव", "5 मिनट में लोन",
    ],
    "digital_arrest_scam": [
        "digital arrest", "arrest warrant",
        "case registered", "under investigation",
        "illegal parcel", "money laundering",
        "freeze account", "police case",
        "video call now", "prove innocence",
        # Hindi variants
        "डिजिटल अरेस्ट", "गिरफ्तारी वारंट", "मनी लॉन्ड्रिंग",
        "पुलिस केस", "निर्दोषिता साबित",
    ],
    "challan_scam": [
        "pending challan", "traffic violation",
        "pay fine", "license suspended",
        "unpaid fine", "vehicle violation",
        "e-challan link",
        # Hindi variants
        "चालान", "ई-चालान", "जुर्माना भरें", "लाइसेंस निलंबित",
    ],
    "scheme_scam": [
        "pm kisan", "pension benefit",
        "government scheme", "subsidy",
        "bonus payment", "extra payment",
        "verify aadhaar",
        # Hindi variants
        "सरकारी योजना", "सब्सिडी", "आधार वेरिफाई", "पेंशन लाभ",
        "पीएम किसान",
    ],
    "family_emergency_scam": [
        "road accident", "hospitalised",
        "medical emergency", "need urgent help",
        "send money urgently", "in hospital",
        # Hindi variants
        "सड़क दुर्घटना", "अस्पताल में", "मेडिकल इमरजेंसी",
        "तुरंत पैसे भेजें",
    ],
    "scholarship_scam": [
        "scholarship", "education grant",
        "student benefit", "claim scholarship",
        # Hindi variants
        "छात्रवृत्ति", "शिक्षा अनुदान",
    ],
}

# ---------------------------------------------------------------------------
# Red Flag Rules  (Phase 3)
# Maps scam category → human-readable warning shown in results.
# A category can trigger multiple flags; flags are deduplicated before return.
# ---------------------------------------------------------------------------

RED_FLAG_RULES = {
    "urgency":                 "Contains urgent language",
    "otp_scam":                "Mentions OTP / verification code",
    "upi_scam":                "Mentions UPI payment or PIN",
    "prize_scam":              "Claims reward or prize",
    "bank_scam":               "Threatens account block or KYC action",
    "tax_scam":                "References tax refund or PAN/Aadhaar",
    "delivery_scam":           "Mentions failed delivery or parcel issue",
    "loan_scam":               "Promises instant loan or approval",
    "digital_arrest_scam":     "Uses digital arrest or legal threat language",
    "challan_scam":            "Mentions traffic fine or e-challan",
    "scheme_scam":             "References government scheme or subsidy",
    "family_emergency_scam":   "Claims family emergency requiring money",
    "scholarship_scam":        "Mentions scholarship or education grant",
}


# ---------------------------------------------------------------------------
# Category Risk Weights  (Phase 4)
# Each value represents how many risk points that category contributes.
# Higher = more dangerous signal.
# ---------------------------------------------------------------------------

CATEGORY_WEIGHTS = {
    "upi_scam":              30,
    "otp_scam":              35,
    "bank_scam":             30,
    "urgency":               15,
    "prize_scam":            25,
    "tax_scam":              25,
    "delivery_scam":         20,
    "loan_scam":             20,
    "digital_arrest_scam":   40,
    "challan_scam":          25,
    "scheme_scam":           20,
    "family_emergency_scam": 30,
    "scholarship_scam":      20,
}

# ---------------------------------------------------------------------------
# URL Risk Constants  (Phase 5)
# ---------------------------------------------------------------------------

# TLDs frequently abused in phishing campaigns (free / low-cost / unregulated)
SUSPICIOUS_TLDS = {
    "xyz", "top", "gq", "tk", "ml", "cf", "click", "zip", "work",
}

# Well-known Indian and global brands commonly impersonated in scam URLs
KNOWN_BRANDS = {
    "paytm", "phonepe", "gpay", "googlepay", "amazon",
    "flipkart", "sbi", "hdfc", "icici", "axis",
}


# ---------------------------------------------------------------------------
# Keyword Detection  (Phase 3)
# ---------------------------------------------------------------------------

def detect_keywords(text: str) -> dict:
    """
    Scan input text against SCAM_PATTERNS and return all matches.

    Args:
        text: Raw input string (will be lowercased internally).

    Returns:
        {
            "matched_categories": list of category names that matched,
            "matched_keywords":   list of individual keywords that matched,
        }
    """
    lowered = text.lower()
    matched_categories: list = []
    matched_keywords:   list = []

    for category, keywords in SCAM_PATTERNS.items():
        for keyword in keywords:
            if keyword in lowered:
                # Record category once even if multiple keywords hit
                if category not in matched_categories:
                    matched_categories.append(category)
                # Record each individual keyword match
                if keyword not in matched_keywords:
                    matched_keywords.append(keyword)

    return {
        "matched_categories": matched_categories,
        "matched_keywords":   matched_keywords,
    }


def build_red_flags(matched_categories: list) -> list:
    """
    Convert a list of matched category names into human-readable red flag strings.

    Args:
        matched_categories: Output from detect_keywords().

    Returns:
        Deduplicated list of red flag description strings.
    """
    flags = []
    for category in matched_categories:
        flag = RED_FLAG_RULES.get(category)
        if flag and flag not in flags:
            flags.append(flag)
    return flags


# ---------------------------------------------------------------------------
# URL Risk Analysis  (Phase 5)
# ---------------------------------------------------------------------------

def analyze_url_risk(url_info: dict) -> dict:
    """
    Score a single parsed URL for domain-level phishing indicators.

    Checks:
      - Suspicious TLD (e.g. .xyz, .tk)
      - Brand name + hyphen pattern (impersonation signal)
      - Excessively long domain name

    Args:
        url_info: A dict returned by parse_url() with keys:
                  full_url, domain, subdomain, suffix.

    Returns:
        {
            "url_risk":  int  — risk points contributed by this URL,
            "url_flags": list — human-readable flag strings,
        }
    """
    risk  = 0
    flags = []

    domain = url_info["domain"].lower()
    suffix = url_info["suffix"].lower()

    # ── Check 1: Suspicious TLD ───────────────────────────────────────────────
    if suffix in SUSPICIOUS_TLDS:
        risk += 25
        flags.append(f"Uses suspicious domain suffix (.{suffix})")

    # ── Check 2: Brand impersonation (brand name + hyphen in domain) ──────────
    for brand in KNOWN_BRANDS:
        if brand in domain and "-" in domain:
            risk += 30
            flags.append(f"Possible impersonation of '{brand}'")
            break  # one impersonation flag per URL is enough

    # ── Check 3: Abnormally long domain ───────────────────────────────────────
    if len(domain) > 20:
        risk += 10
        flags.append(f"Unusually long domain name ({len(domain)} chars)")

    return {
        "url_risk":  risk,
        "url_flags": flags,
    }


# ---------------------------------------------------------------------------
# Core Function  (updated in Phase 3)
# ---------------------------------------------------------------------------

def detect_phish(input_data: str) -> dict:
    """
    Core detection function.

    Pipeline:
        1. Extract + parse URLs              (Phase 2)
        2. Match scam keywords               (Phase 3)
        3. Sum category weights + bonuses    (Phase 4)
        4. Analyse each URL for domain risk  (Phase 5)
        5. Merge URL risk into total score   (Phase 5)
        6. Decide is_scam (score >= 40)      (Phase 4)
        7. Build full explanation markdown   (Phase 4/5)

    Args:
        input_data: Raw text or URL string to analyse.

    Returns:
        A fully populated risk assessment dict.
    """
    # ── Phase 2: URL extraction & parsing ────────────────────────────────────
    detected_urls = extract_urls(input_data)
    url_analysis  = [parse_url(u) for u in detected_urls]

    # ── Phase 3: Keyword + category matching ─────────────────────────────────
    keyword_result     = detect_keywords(input_data)
    matched_categories = keyword_result["matched_categories"]
    matched_keywords   = keyword_result["matched_keywords"]
    red_flags          = build_red_flags(matched_categories)

    # ── Phase 4: Text-based risk scoring ─────────────────────────────────────
    risk_score = 0

    for category in matched_categories:
        risk_score += CATEGORY_WEIGHTS.get(category, 10)

    # Bonus for messages that combine multiple threat signals
    if len(matched_categories) >= 2:
        risk_score += 10
    if len(matched_categories) >= 3:
        risk_score += 10

    # ── Phase 5: URL-based risk scoring ──────────────────────────────────────
    url_risk_total = 0
    url_flags_all  = []

    for url in url_analysis:
        result = analyze_url_risk(url)
        url_risk_total += result["url_risk"]
        url_flags_all.extend(result["url_flags"])

    # Merge URL risk into the running total, then cap
    risk_score += url_risk_total
    risk_score  = min(risk_score, 100)

    # Append URL flags into the unified red_flags list (deduplicated)
    for flag in url_flags_all:
        if flag not in red_flags:
            red_flags.append(flag)

    # ── Phase 4: Decision ─────────────────────────────────────────────────────
    is_scam = risk_score >= 40

    # Primary category: highest-weight text category, or "url_scam" if only URL signals fired
    if matched_categories:
        final_category = max(matched_categories, key=lambda c: CATEGORY_WEIGHTS.get(c, 0))
    elif url_flags_all:
        final_category = "url_scam"
    else:
        final_category = "safe"

    # ── Phase 4: Impact + Action ──────────────────────────────────────────────
    if is_scam:
        impact = "Potential financial loss or identity theft."
        action = "Do NOT click any links or share sensitive information."
    else:
        impact = "Low risk."
        action = "No immediate threat detected."

    # ── Phase 4/5: Explanation markdown ──────────────────────────────────────
    category_list = ", ".join(matched_categories) if matched_categories else "None"
    keyword_list  = ", ".join(matched_keywords)   if matched_keywords   else "None"
    flag_list     = "\n".join(f"- {f}" for f in red_flags) if red_flags else "- None"

    explanation = f"""### Scam Analysis Result

**Risk Score:** {risk_score}/100  
**Decision:** {"⚠️ SCAM DETECTED" if is_scam else "✅ Likely Safe"}  
**Primary Category:** {final_category.replace("_", " ").title()}  
**Detected Categories:** {category_list}  

### Why this is flagged:
{flag_list}

**Matched keywords:** {keyword_list}  
**URLs found:** {len(detected_urls)}  

### Recommendation:
{action}

*Impact: {impact}*"""

    # Append URL-specific risk section if any URL flags were raised
    if url_flags_all:
        url_flag_lines = "\n- ".join(url_flags_all)
        explanation += f"\n\n### URL Risk Signals:\n- {url_flag_lines}"

    # ── Final response ─────────────────────────────────────────────────────────
    return {
        "is_scam":              is_scam,
        "risk_score":           risk_score,
        "category":             final_category,
        "red_flags":            red_flags,
        "impact":               impact,
        "action":               action,
        "explanation_markdown": explanation,
        "detected_urls":        detected_urls,
        "url_analysis":         url_analysis,
        "matched_categories":   matched_categories,
        "matched_keywords":     matched_keywords,
    }


# ---------------------------------------------------------------------------
# API Routes  (unchanged)
# ---------------------------------------------------------------------------

@app.get("/health", summary="Health check")
def health_check():
    """Returns service status. Use this to verify the API is running."""
    return {"status": "ok"}


@app.post("/detect", summary="Analyse text or URL for phishing/scam signals")
def detect(request: DetectRequest):
    """
    Accepts a JSON body with `text` or `url` (or both), and an optional `language`.

    Returns the full technical analysis plus two localised user-facing fields:
      - user_message : plain verdict in the requested language
      - user_action  : plain safety instruction in the requested language
    """
    if not request.text and not request.url:
        raise HTTPException(
            status_code=422,
            detail="Request must include at least one of: 'text', 'url'",
        )

    input_data = request.text if request.text else request.url

    # Resolve language template — fall back to English for unsupported codes
    lang     = request.language if request.language in LANGUAGE_TEMPLATES else "en"
    template = LANGUAGE_TEMPLATES[lang]

    result = detect_phish(input_data)

    # Inject localised fields into the response
    result["user_message"] = template["scam"] if result["is_scam"] else template["safe"]
    result["user_action"]  = template["action"]

    return result


# ---------------------------------------------------------------------------
# CLI Mode  (unchanged)
# ---------------------------------------------------------------------------

def run_cli():
    """Interactive CLI: prompts for input and language, runs detect_phish(), prints result."""
    print("=" * 50)
    print("  PhishGuard CLI — Scam Detection Tool")
    print("=" * 50)
    print("Enter the text or URL you want to analyse.")
    print("(Ctrl+C to quit)\n")

    try:
        user_input = input("Input : ").strip()
        lang_input = input("Language [en/hi/mr, default en]: ").strip() or "en"
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        return

    if not user_input:
        print("No input provided. Exiting.")
        return

    lang     = lang_input if lang_input in LANGUAGE_TEMPLATES else "en"
    template = LANGUAGE_TEMPLATES[lang]

    result = detect_phish(user_input)
    result["user_message"] = template["scam"] if result["is_scam"] else template["safe"]
    result["user_action"]  = template["action"]

    # Print the user-facing verdict prominently, then the full JSON
    print(f"\n{result['user_message']}")
    print(f"👉 {result['user_action']}\n")
    print("--- Full Result ---")
    print(json.dumps(result, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--serve" in sys.argv:
        uvicorn.run("phishguard:app", host="0.0.0.0", port=8000, reload=True)
    else:
        run_cli()