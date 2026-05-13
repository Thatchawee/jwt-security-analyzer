from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from analyzer.decode import decode_jwt
from analyzer.alg_check import check_static_vulnerabilities
from analyzer.rsa_keygen import generate_custom_rsa_keys

# TODO (Person 2): Import attack modules here later
# from analyzer.secret_cracker import crack_hs256
# from analyzer.alg_check import check_alg_confusion

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

@app.post("/analyze")
def analyze_endpoint(request: TokenRequest):
    """Main endpoint to decode and analyze the JWT."""
    # 1. Decode Token
    decoded = decode_jwt(request.token)
    if "error" in decoded:
        raise HTTPException(status_code=400, detail=decoded["error"])
        
    # 2. Run Static Analysis (Person 1)
    analysis = check_static_vulnerabilities(decoded)
    
    # 3. Run Active Attacks (Person 2's hooks)
    # if decoded["header"].get("alg") == "HS256":
    #     cracked = crack_hs256(request.token)
    #     if cracked:
    #         analysis["vulnerabilities"].append({...})
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)