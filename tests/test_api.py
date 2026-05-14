from fastapi.testclient import TestClient
from app import app
import hmac
import hashlib
import base64
import json

client = TestClient(app)

def test_analyze_endpoint_none_alg():
    # Token with alg:none
    token = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    
    response = client.post("/analyze", json={"token": token})
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    
    # Check if the static analyzer caught it
    vulns = data["analysis"]["vulnerabilities"]
    assert any(v["type"] == "alg: none Attack" for v in vulns)

def test_rsa_keygen_endpoint():
    response = client.get("/generate-rsa")
    assert response.status_code == 200
    
    data = response.json()
    assert data["status"] == "success"
    assert "public_key" in data["keys"]
    assert "private_key" in data["keys"]
    assert "n" in data["keys"]["public_key"]

def test_alg_confusion_endpoint():
    # Safe dummy token
    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dummy_sig"
    dummy_pub_key = "---BEGIN PUBLIC KEY---\nDummyKey\n---END PUBLIC KEY---"
    
    response = client.post(
        "/attack/alg-confusion", 
        json={"token": token, "public_key_pem": dummy_pub_key}
    )
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert "forged_token" in data
    # The new header should decode to alg: HS256
    assert data["forged_token"].startswith("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

# --- Helper Function for Testing ---
def generate_test_token(secret: str) -> str:
    """Dynamically creates a mathematically valid HS256 JWT for testing."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode('utf-8').rstrip('=')
    payload = base64.urlsafe_b64encode(b'{"user":"tester"}').decode('utf-8').rstrip('=')
    msg = f"{header}.{payload}".encode('utf-8')
    
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode('utf-8'), msg, hashlib.sha256).digest()
    ).decode('utf-8').rstrip('=')
    
    return f"{header}.{payload}.{sig}"

# --- New Test Cases ---
def test_analyze_cracked_secret():
    """Tests if the analyzer successfully cracks a weak secret from the wordlist."""
    weak_secret = "admin" 
    token = generate_test_token(weak_secret)
    
    response = client.post("/analyze", json={"token": token})
    assert response.status_code == 200
    
    data = response.json()
    
    # Navigate through the JSON response to find the attack results
    attack_result = data["analysis"].get("active_attacks", {}).get("dictionary_attack", {})
    
    assert attack_result.get("cracked") is True
    assert attack_result.get("secret") == weak_secret
    
    # Verify that the cracked secret was successfully added to the vulnerabilities list
    vulns = [v["type"] for v in data["analysis"]["vulnerabilities"]]
    assert "Weak HS256 Secret" in vulns

def test_analyze_strong_secret():
    """Tests if the analyzer correctly handles a secret that is NOT in the wordlist."""
    strong_secret = "Super_Secure_Uncrackable_Secret_999!!!"
    token = generate_test_token(strong_secret)
    
    response = client.post("/analyze", json={"token": token})
    assert response.status_code == 200
    
    data = response.json()
    attack_result = data["analysis"].get("active_attacks", {}).get("dictionary_attack", {})
    
    # It should finish scanning the wordlist and return False
    assert attack_result.get("cracked") is False