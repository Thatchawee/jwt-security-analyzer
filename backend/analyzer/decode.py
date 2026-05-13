import base64
import json

def base64url_decode(input_str: str) -> bytes:
    """Safely decodes Base64Url strings by fixing missing padding."""
    rem = len(input_str) % 4
    if rem > 0:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str)

def decode_jwt(token: str) -> dict:
    """Splits and decodes the JWT parts without verifying the signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid JWT format. Expected exactly 3 parts separated by dots."}

    try:
        header = json.loads(base64url_decode(parts[0]).decode('utf-8'))
        payload = json.loads(base64url_decode(parts[1]).decode('utf-8'))
        signature = parts[2] # Keep signature as raw string
        
        return {
            "header": header,
            "payload": payload,
            "signature": signature
        }
    except Exception as e:
        return {"error": f"Decoding failed: {str(e)}"}