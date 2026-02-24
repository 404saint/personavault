from datetime import datetime, timedelta

# Risk multipliers for tags
TAG_MULTIPLIERS = {
    "darkweb": 1.5,
    "high-risk": 1.3,
    "financial": 1.1,
    "social": 1.0,
    "burner": 0.9,
    "long-term": 0.8,
    "throwaway": 1.0
}

# Tier mapping
RISK_TIERS = [
    (0, 19, "Low"),
    (20, 39, "Medium"),
    (40, 69, "High"),
    (70, 9999, "Critical")
]

def compute_risk(persona: dict) -> dict:
    """
    Compute dynamic risk score and level for a persona.
    """
    base_score = 0

    # --- Platforms used ---
    usage_list = persona.get("usage", [])
    platforms = set(u["platform"] for u in usage_list)
    base_score += len(platforms) * 5  # 5 pts per platform

    # --- Reuse frequency ---
    username_count = {}
    for u in usage_list:
        username_count[u["username"]] = username_count.get(u["username"], 0) + 1
    reuse_penalty = sum(max(0, count - 1) * 3 for count in username_count.values())  # 3 pts per reused username
    base_score += reuse_penalty

    # --- High-risk tags ---
    for tag in persona.get("tags", []):
        multiplier = TAG_MULTIPLIERS.get(tag, 1.0)
        base_score *= multiplier

    # --- Dormant reuse penalty ---
    if usage_list:
        last_used = max(datetime.fromisoformat(u.get("date")) for u in usage_list)
        if datetime.now() - last_used > timedelta(days=365):
            base_score *= 1.2  # 20% increase if reused after a year of dormancy

    # --- Map score to tier ---
    for low, high, level in RISK_TIERS:
        if low <= base_score <= high:
            risk_level = level
            break
    else:
        risk_level = "Critical"

    return {
        "score": round(base_score, 1),
        "level": risk_level
    }
