# 🔐 JWT Security Analyzer

> A web-based tool that audits JSON Web Tokens (JWT) for common security vulnerabilities and provides actionable fix recommendations.

---

## 📌 Overview

JWT (JSON Web Token) is widely used for authentication in modern web applications. However, misconfigurations and weak implementations can lead to critical security flaws. **JWT Security Analyzer** helps developers detect these vulnerabilities before attackers do.

This project was built as part of a **Network and Computer Security** course mini-project.

---

## 🚨 Vulnerabilities Detected

| Vulnerability | Description | Severity |
|---|---|---|
| `alg: none` Attack | Token accepted without any signature | 🔴 Critical |
| Weak HS256 Secret | Secret crackable via dictionary attack | 🔴 Critical |
| Algorithm Confusion | RS256 → HS256 downgrade attack | 🔴 Critical |
| Missing Expiration | No `exp` claim — tokens valid forever | 🟠 High |
| Sensitive Data in Payload | PII or credentials stored unencrypted | 🟡 Medium |

---

## ✨ Features

- **🔍 JWT Decoder** — Inspect header, payload, and signature clearly
- **⚠️ Algorithm Checker** — Flags dangerous algorithms (`none`, weak HS256)
- **🔓 Secret Cracker** — Dictionary attack on HS256 tokens to test secret strength
- **🔄 Algorithm Confusion Tester** — Detects RS256 → HS256 downgrade vulnerability
- **🔑 RSA Key Generator** — Custom RSA key generation for RS256 token testing *(bonus)*
- **💡 Auto Fix Recommendations** — Tells you exactly how to fix each issue found

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + TailwindCSS |
| Backend | Python (FastAPI) |
| Crypto | Custom RSA implementation + `cryptography` library |
| Dictionary | Common JWT secret wordlists |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/jwt-security-analyzer.git
cd jwt-security-analyzer

# Backend setup
cd backend
pip install -r requirements.txt
uvicorn app:app --reload

# Frontend setup (new terminal)
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 📁 Project Structure

```
jwt-security-analyzer/
├── frontend/               # React web UI
│   ├── src/
│   │   ├── components/
│   │   └── App.jsx
│   └── package.json
├── backend/                # FastAPI server
│   ├── analyzer/
│   │   ├── decode.py       # JWT decode logic
│   │   ├── alg_check.py    # Algorithm vulnerability checks
│   │   ├── secret_cracker.py  # HS256 dictionary attack
│   │   └── rsa_keygen.py   # Custom RSA implementation (bonus)
│   ├── app.py
│   └── requirements.txt
├── wordlists/              # Secret dictionaries
├── tests/
└── report/                 # Project report (PDF)
```

---

## 📖 How It Works

1. **Paste your JWT token** into the analyzer
2. The tool **decodes and inspects** the header and payload
3. It runs **automated security checks** across all vulnerability categories
4. You receive a **detailed report** with severity ratings and fix recommendations

### Example Output

```
Token: eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

[CRITICAL] Algorithm 'none' detected — signature not verified
[HIGH]     No expiration claim (exp) found
[INFO]     Payload contains field 'user' — ensure no sensitive data is exposed

Recommendations:
  ✅ Use HS256 with a strong random secret (min 256 bits)
  ✅ Always include 'exp' claim with short TTL (15–60 min)
```

---


---

## 📚 References

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [PortSwigger — JWT Attacks](https://portswigger.net/web-security/jwt)
- [OWASP — JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
