# ⚖️ LawFinder AI — AI-Powered LegalTech Triage & Solicitor Matching Platform

**LawFinder AI** is a full-stack LegalTech web application designed to help Hong Kong SMEs, startups, and individuals obtain instant, structured AI preliminary legal assessments and securely connect with verified local solicitors.

> **Disclaimer:** *This project was developed as an independent full-stack & security engineering portfolio piece. The AI assistant provides preliminary semantic analysis and general legal information only—it does not constitute formal legal advice or establish a solicitor-client relationship.*

---

## ✨ Key Features

### 🤖 AI Legal Triage & Structured Metadata Extraction
* **Domain-Specific Consultation Flows:** Separate triage pipelines tailored for **Personal Civil/Criminal** matters and **Corporate/Startup** disputes across 16 Hong Kong legal domains.
* **Local LLM Integration (Qwen 2.5):** Connects to local OpenAI-compatible inference endpoints (LM Studio / Qwen 2.5) with custom system prompts enforcing structured Markdown legal breakdowns.
* **Strict Schema Validation:** Uses **Pydantic** (`CaseMetadata`) to validate LLM JSON outputs, automatically extracting case categories, estimated claim amounts, technical summaries, and evidence strength scores (`1–10`).

### 🔐 Enterprise-Grade Security & PDPO Compliance
* **Encryption at Rest:** Implements **Fernet symmetric encryption** (`cryptography`) for sensitive database fields, including case descriptions, client real names, opponent names (for conflict checks), contact numbers, and chat messages.
* **Multi-Factor & Role-Based Access Control (RBAC):** Supports distinct workflows and dynamic UI routing for **Clients**, **Practicing Solicitors**, and **Administrators**, protected by **TOTP 2FA (`PyOTP`)** for the hidden admin portal.
* **Authentication & Anti-Abuse:** Secures credentials with **Bcrypt** salted hashing, enforces mandatory password resets for newly onboarded solicitors, applies login rate-limiting (5 attempts per 15-minute window), and sanitizes rendered HTML to prevent XSS.
* **Data Minimization:** Includes one-click hard-deletion for AI chat histories, case withdrawals, and cascading account erasure in alignment with Hong Kong's *Personal Data (Privacy) Ordinance (PDPO)*.

### 🤝 Dual-Approval Matching & Case Lifecycle Engine
* **Conflict Check & Marketplace:** Verified solicitors filter anonymized cases by domain, category, and evidence score, completing a mandatory conflict-of-interest check before unlocking a case.
* **Mutual Consent Unlock:** Clients review the interested solicitor's firm, specialty, experience, and peer ratings before approving the match and releasing their contact details.
* **Real-Time Milestone Tracking:** Auto-refreshing (`st.fragment`) encrypted chat rooms and state-machine milestone tracking (*Pending Approval → Consultation → Sued → Mediation → Closing Pending → Closed*).
* **Admin Verification Console:** Built-in administrative dashboard to cross-check solicitor credentials against the Hong Kong Law Society registry, manage user/solicitor accounts, and monitor platform cases.

---

## 🛠️ Tech Stack

* **Frontend & Framework:** Python, Streamlit (Session State & Auto-Refreshing Fragments)
* **AI & Validation:** OpenAI Python SDK (Local LLM / Qwen 2.5), Pydantic
* **Database:** SQLite3 (Relational schema with foreign keys & cascading deletes)
* **Security & Auth:** Cryptography (Fernet AES-128-CBC + HMAC), Bcrypt, PyOTP (TOTP 2FA), Regex/HTML Sanitization

---

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone [https://github.com/paklon/LawFinder-AI.git](https://github.com/paklon/LawFinder-AI.git)
cd LawFinder-AI
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Secrets (FERNET_KEY)
* Generate a valid Fernet encryption key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
* Create .streamlit/secrets.toml and add your generated key:
```bash
FERNET_KEY = "your-generated-fernet-key-here"
```

### 4.Start Local LLM Server (Optional for AI Chat)
* Run LM Studio (or any OpenAI-compatible local server) serving qwen2.5-1.5b at http://localhost:1234/v1. 

### 5. Run the Application
```bash
streamlit run web_app.py
```
* To access the hidden Admin Portal, append ?access=admin_portal_secure to the local URL (e.g., http://localhost:8501/?access=admin_portal_secure).
