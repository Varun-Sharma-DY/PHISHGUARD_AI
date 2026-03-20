"""
PhishGuard — SQLite Caching Layer
==================================
Standalone, reusable caching module.

Tables:
  cache (key TEXT PRIMARY KEY, value TEXT, timestamp REAL)

TTL constants (used by phishguard.py):
  CACHE_TTL_DETECTION  = 3600   (1 hour)   — full detection results
  CACHE_TTL_TRANSLATE  = 86400  (24 hours) — translation results
  CACHE_TTL_URL        = 3600   (1 hour)   — URL risk analysis

Rules:
  ✅ Cache: final detection results, translations, URL risk scores
  ❌ Never cache: raw user input, partial pipeline results,
                  LLM intermediate responses
"""
import sqlite3
import json
import time

DB_PATH = "cache.db"

# =============================================================================
# TTL Constants
# =============================================================================

CACHE_TTL_DETECTION = 3600    # 1 hour  — full phishing detection result
CACHE_TTL_TRANSLATE = 86400   # 24 hours — translation (text rarely changes)
CACHE_TTL_URL       = 3600    # 1 hour  — URL risk analysis


# =============================================================================
# Init
# =============================================================================

def init_cache():
    """
    Create the SQLite DB and cache table if they don't exist.
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    Call once on app startup.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            key       TEXT PRIMARY KEY,
            value     TEXT,
            timestamp REAL
        )
    """)

    conn.commit()
    conn.close()
    print(f"[Cache] Initialized — DB: {DB_PATH}")


# =============================================================================
# Get
# =============================================================================

def get_cache(key: str, ttl: int):
    """
    Retrieve a cached value by key.

    Returns the deserialized value if found and within TTL.
    Returns None if key doesn't exist or is expired.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT value, timestamp FROM cache WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    value, timestamp = row

    if time.time() - timestamp > ttl:
        # Expired — treat as cache miss
        return None

    return json.loads(value)


# =============================================================================
# Set
# =============================================================================

def set_cache(key: str, value):
    """
    Store a value in cache with current timestamp.
    Uses INSERT OR REPLACE so existing keys are overwritten cleanly.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT OR REPLACE INTO cache (key, value, timestamp) VALUES (?, ?, ?)",
        (key, json.dumps(value, ensure_ascii=False), time.time())
    )

    conn.commit()
    conn.close()


# =============================================================================
# Key Normalization
# =============================================================================

def normalize_url(url: str) -> str:
    """
    Normalize a URL for use as a cache key.
    Strips whitespace and lowercases to avoid duplicate entries like:
      url:example.com vs url:EXAMPLE.com vs url:http://example.com/
    """
    return url.strip().lower()


def normalize_text(text: str) -> str:
    """
    Normalize free text for cache keys.
    Strips whitespace and lowercases.
    """
    return text.strip().lower()


# =============================================================================
# Cleanup (optional — removes expired rows)
# =============================================================================

def cleanup_cache(ttl: int):
    """
    Delete all cache rows older than ttl seconds.
    Call on startup or periodically to keep DB size in check.
    """
    conn        = sqlite3.connect(DB_PATH)
    cursor      = conn.cursor()
    expiry_time = time.time() - ttl

    cursor.execute("DELETE FROM cache WHERE timestamp < ?", (expiry_time,))
    deleted = cursor.rowcount

    conn.commit()
    conn.close()
    print(f"[Cache] Cleanup — removed {deleted} expired entries")


# =============================================================================
# Stats (useful for demo / debugging)
# =============================================================================

def cache_stats() -> dict:
    """
    Return basic stats about the cache for debugging or health endpoint.
    """
    conn   = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM cache")
    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM cache WHERE key LIKE 'detect:%'"
    )
    detection_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM cache WHERE key LIKE 'translate:%'"
    )
    translation_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM cache WHERE key LIKE 'url:%'"
    )
    url_count = cursor.fetchone()[0]

    conn.close()

    return {
        "total_entries":      total,
        "detection_entries":  detection_count,
        "translation_entries": translation_count,
        "url_entries":        url_count,
    }