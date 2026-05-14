from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from analyzer.decode import decode_jwt
from analyzer.alg_check import check_static_vulnerabilities
from analyzer.alg_check import generate_confusion_token
from analyzer.rsa_keygen import generate_custom_rsa_keys
from analyzer.secret_cracker import crack_hs256

app = FastAPI(title="JWT Security Analyzer API")

# Allow Frontend (Person 3) to communicate with the Backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for local development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TokenRequest(BaseModel):
    token: str

class ConfusionRequest(BaseModel):
    token: str
    public_key_pem: str

@app.post("/analyze")
def analyze_endpoint(request: TokenRequest):
    """Main endpoint to decode and analyze the JWT."""
    # 1. Decode Token
    decoded = decode_jwt(request.token)
    if "error" in decoded:
        raise HTTPException(status_code=400, detail=decoded["error"])
        
    # 2. Run Static Analysis (Person 1)
    analysis = check_static_vulnerabilities(decoded)
    
    # 3. Run Active Attacks (Person 2)
    header = decoded.get("header", {})
    alg = header.get("alg", "").upper()
    
    if alg == "HS256":
        crack_result = crack_hs256(request.token)
        analysis["active_attacks"] = {"dictionary_attack": crack_result}
        
        # If cracked, add it to vulnerabilities
        if crack_result.get("cracked"):
            analysis["vulnerabilities"].append({
                "type": "Weak HS256 Secret",
                "severity": "CRITICAL",
                "description": crack_result["message"]
            })
            analysis["recommendations"].append("Use a strong, cryptographically random secret of at least 256 bits (32 bytes).")

    return {
        "status": "success",
        "decoded": decoded,
        "analysis": analysis
    }

@app.get("/generate-rsa")
def rsa_keygen_endpoint():
    """Generates a custom RSA keypair for testing RS256 downgrades."""
    # Using 1024 bits to ensure the API responds quickly during grading/demos
    keys = generate_custom_rsa_keys(bits=1024)
    return {
        "status": "success",
        "keys": keys
    }

@app.post("/attack/alg-confusion")
def alg_confusion_endpoint(request: ConfusionRequest):
    """Endpoint to generate an algorithm confusion payload."""
    result = generate_confusion_token(request.token, request.public_key_pem)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)