def check_static_vulnerabilities(decoded_jwt: dict) -> dict:
    """Checks the decoded JWT for common static misconfigurations."""
    vulnerabilities = []
    recommendations = []

    if "error" in decoded_jwt:
        return {"error": decoded_jwt["error"]}

    header = decoded_jwt.get("header", {})
    payload = decoded_jwt.get("payload", {})

    # 1. Check for 'alg: none' (CRITICAL)
    alg = header.get("alg", "").lower()
    if alg == "none":
        vulnerabilities.append({
            "type": "alg: none Attack",
            "severity": "CRITICAL",
            "description": "Token algorithm is set to 'none'. The token is accepted without any signature verification."
        })
        recommendations.append("Backend must strictly enforce allowed algorithms (e.g., ['HS256', 'RS256']) and explicitly reject 'none'.")

    # 2. Check for missing expiration (HIGH)
    if "exp" not in payload:
        vulnerabilities.append({
            "type": "Missing Expiration",
            "severity": "HIGH",
            "description": "No 'exp' (expiration) claim found. This token is valid indefinitely if stolen."
        })
        recommendations.append("Always include an 'exp' claim with a short Time-To-Live (TTL), such as 15–60 minutes.")

    # 3. Check for Sensitive Data in Payload (MEDIUM)
    sensitive_keywords = ["password", "pass", "pwd", "ssn", "secret", "credit_card", "cc", "token"]
    found_sensitive = [k for k in payload.keys() if any(sk in k.lower() for sk in sensitive_keywords)]
    
    if found_sensitive:
        vulnerabilities.append({
            "type": "Sensitive Data in Payload",
            "severity": "MEDIUM",
            "description": f"Potential sensitive data found in claims: {', '.join(found_sensitive)}."
        })
        recommendations.append("Never store PII or credentials unencrypted in the JWT payload. Anyone can decode and read this.")

    return {
        "vulnerabilities": vulnerabilities,
        "recommendations": recommendations
    }