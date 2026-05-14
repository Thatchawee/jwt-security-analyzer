import hmac
import hashlib
import base64
import os

def base64url_encode(data: bytes) -> str:
    """Encodes bytes into a Base64Url string without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def crack_hs256(token: str, wordlist_path: str = "../wordlists/scraped-JWT-secrets.txt") -> dict:
    """
    Performs a dictionary attack on an HS256 JWT.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid token format."}
    
    # We sign the "header.payload" portion
    header_payload = f"{parts[0]}.{parts[1]}".encode('utf-8')
    original_signature = parts[2]

    # Resolve absolute path to wordlist (useful when running from different directories)
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    full_wordlist_path = os.path.join(base_dir, "wordlists", "scraped-JWT-secrets.txt")

    if not os.path.exists(full_wordlist_path):
        return {"error": f"Wordlist not found at {full_wordlist_path}"}

    try:
        with open(full_wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                secret = line.strip()
                if not secret:
                    continue
                
                # Generate new signature using the current word as the secret
                sig = hmac.new(secret.encode('utf-8'), header_payload, hashlib.sha256).digest()
                encoded_sig = base64url_encode(sig)

                # Use compare_digest to prevent timing attacks
                if hmac.compare_digest(encoded_sig, original_signature):
                    return {
                        "cracked": True, 
                        "secret": secret,
                        "message": f"CRITICAL: Token secret cracked! The secret is '{secret}'."
                    }
                    
        return {"cracked": False, "message": "Token safe against current wordlist."}
    except Exception as e:
        return {"error": str(e)}