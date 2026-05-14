from analyzer.decode import decode_jwt
from analyzer.alg_check import check_static_vulnerabilities
from analyzer.secret_cracker import crack_hs256

def test_decode_valid_jwt():
    # A standard JWT (Header: {"alg":"HS256","typ":"JWT"}, Payload: {"user":"admin"})
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    result = decode_jwt(token)
    
    assert "error" not in result
    assert result["header"]["alg"] == "HS256"
    assert result["payload"]["user"] == "admin"
    assert result["signature"] != ""

def test_decode_invalid_format():
    token = "not.a.valid.token.format"
    result = decode_jwt(token)
    
    assert "error" in result
    assert "Expected exactly 3 parts" in result["error"]

def test_static_vulnerabilities():
    # Mocking a decoded JWT with critical flaws
    decoded_mock = {
        "header": {"alg": "none"},
        "payload": {"password": "supersecretpassword123"},
        "signature": ""
    }
    
    analysis = check_static_vulnerabilities(decoded_mock)
    vulnerabilities = [v["type"] for v in analysis["vulnerabilities"]]
    
    assert "alg: none Attack" in vulnerabilities
    assert "Missing Expiration" in vulnerabilities
    assert "Sensitive Data in Payload" in vulnerabilities

def test_crack_hs256_invalid_format():
    """Tests that the secret cracker gracefully rejects tokens that don't have exactly 3 parts."""
    # A token missing the signature part
    malformed_token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ" 
    
    result = crack_hs256(malformed_token)
    
    assert "error" in result
    assert "Invalid token format" in result["error"]

def test_crack_hs256_garbage_data():
    """Tests that the cracker handles a valid 3-part structure, but with complete garbage data."""
    # 3 parts separated by dots, but completely invalid JWT data
    garbage_token = "not_a_real_header.not_a_real_payload.fake_signature"
    
    result = crack_hs256(garbage_token)
    
    # It shouldn't crash or throw a Python exception. 
    # It should just scan the wordlist, fail to match the "fake_signature", and return False.
    assert "error" not in result
    assert result.get("cracked") is False
    assert "safe against current wordlist" in result.get("message", "")