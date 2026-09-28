# PrivacyGuard Edge

**Universal On-Device Data Loss Prevention (DLP) & Privacy Redaction Engine**

PrivacyGuard Edge is a privacy-first, on-device Data Loss Prevention (DLP) system designed to scan documents, source code, spreadsheets, logs, configs, and images. It automatically detects, verifies, classifies, and redacts sensitive personal data, government identifiers, financial records, credentials, and API secrets.

Everything runs 100% locally on your machine with zero external cloud calls, and temporary uploads are immediately wiped upon analysis.

---

## Key Features & Capabilities

### 1. Modern UI & Rich Themes
- **Dark & Light Mode Themes**: Cyber-slate dark theme with glowing neon accents and crisp light theme with persistent user preference.
- **Interactive Risk Dashboard**: Real-time SVG circular gauge meter, dynamic risk scores, and severity breakdowns.
- **Side-by-Side & Multi-Tab Viewers**:
  - *Highlighted Document View* with semantic hover cards.
  - *Live Redacted Preview* with on-the-fly style toggling.
  - *Filterable Findings Inventory* with live keyword and severity search.
  - *Side-by-Side Diff* (Original vs Redacted).
- **Direct Text/Code Scanner & Presets**: Analyze raw text or pasted code directly without needing to upload a file, plus 1-click sample presets.

### 2. Universal File Format Support (>10 MB up to 100 MB)
- **Large Uploads**: Configurable upload limits supporting files over 10 MB (up to 100 MB by default).
- **Documents**: PDF, Word (`.docx`, `.doc`), OpenDocument (`.odt`), Rich Text (`.rtf`).
- **Spreadsheets & Data**: Excel (`.xlsx`, `.xls`), CSV (`.csv`), TSV (`.tsv`).
- **Presentations**: PowerPoint (`.pptx`).
- **Structured Data & Configs**: JSON, YAML, XML, HTML, LOG, ENV, SQL, INI, TOML.
- **Source Code**: Python, JavaScript, TypeScript, Java, C/C++, C#, Go, Rust, Ruby, PHP, Shell/Bash.
- **Images (OCR)**: PNG, JPG, JPEG, WEBP, BMP, TIFF via Tesseract OCR.
- **Archives**: ZIP, TAR, GZ (automatically unpacks and scans internal text files).

### 3. High-Accuracy Algorithmic Verification & Detection
- **Government Identifiers**:
  - **Aadhaar Number**: Verified using the **Verhoeff algorithm** (base-10 dihedral checksum) to prevent false positives.
  - **Indian PAN Card**: Format and entity category letter verification (`CPHFATBLJG`).
  - **Passports**: Indian and International Passport patterns.
  - **Voter ID (EPIC)** & **Driving Licence**.
  - **US SSN** & **UK NINO**.
- **Financial Information**:
  - **Credit/Debit Cards**: Validated with the **Luhn Algorithm (Mod 10)** (Visa, Mastercard, Amex, RuPay, Discover).
  - **Bank Accounts** & **IFSC Codes** (RBI bank identifier structure).
  - **UPI IDs** (Google Pay, PhonePe, Paytm, BHIM VPAs).
  - **SWIFT/BIC** & **IBAN**.
  - **Salary & Compensation**: CTC, take-home, and compensation figures.
  - **Crypto Wallets**: Bitcoin (BTC), Ethereum (ETH), Solana (SOL).
- **Credentials & Secrets**:
  - AWS Access Keys (`AKIA...`) & Secret Access Keys.
  - OpenAI API Keys (`sk-...`, `sk-proj-...`).
  - GitHub Personal Access Tokens (`ghp_...`, `github_pat_...`).
  - Google Cloud / Maps API Keys (`AIza...`).
  - Slack Tokens, Stripe Secret/Publishable Keys, JWTs, Private Key Blocks, Database Connection URIs.
- **Personal Information (PII) & Health**:
  - Email addresses, Phone numbers (Indian mobile + international E.164), Dates of Birth, Pincodes/Zip codes.
  - Medical Record Numbers (MRN), patient identifiers, blood groups (HIPAA aligned).
  - Named Entity Recognition (NER) with spaCy.

### 4. Customizable Redaction Modes
- **Typed Labels**: `[REDACTED - EMAIL]`, `[REDACTED - AADHAAR]`, `[REDACTED - API_KEY]`
- **Character Masking**: Preserves character lengths with bullet masks (`••••••••••••`)
- **Solid Blackout**: True redaction with blackout blocks (`████████`)
- **Minimal**: `[REDACTED]`
- **Multi-Format Export**: Download Redacted Text (`.txt`), PDF Audit Report (`.pdf`), Structured Findings (`.json`), or CSV (`.csv`).

---

## Installation & Quick Start

```bash
# Clone the repository and install requirements
pip install -r requirements.txt

# Run the application
python app.py
```

Open your browser at `http://localhost:5000`

---

## Running Test Suite

```bash
python -m pytest
```
