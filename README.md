# 🛡️ Phishing Website Detector

A modern full-stack phishing URL detection system built with **Django**, **Next.js (TSX)**, and **PostgreSQL**. It combines a weighted heuristic scoring engine with real-time threat intelligence from four security vendor APIs to accurately classify URLs as **SAFE**, **SUSPICIOUS**, or **PHISHING** — while minimizing false positives.

---

## ✨ Key Features

- **Multi-layered detection** — 15+ heuristic signals (lexical, WHOIS, SSL, JavaScript, HTML content analysis) combined with external vendor consensus.
- **Vendor-consensus priority** — External API verdicts override noisy heuristic signals. A URL like `checkphish.bolster.ai` won't be flagged just because it contains the word "phish".
- **4 External Security APIs** — Google Safe Browsing, VirusTotal, IPQualityScore, and URLScan.io.
- **Whitelist / Blacklist policies** — Admin-managed domain overrides for instant verdicts.
- **Scan history** — Every scan is persisted with full evidence for audit & review.
- **Chrome Extension** — Real-time phishing interception with a warning page before risky sites load.
- **CLI Scanner** — Quick terminal-based URL scanning via `node index.js`.
- **Glassmorphic UI** — A sleek, modern Next.js frontend with real-time scoring, vote breakdowns, and micro-animations.

---

## 🛠️ Tech Stack

| Layer | Technology | Details |
|---|---|---|
| **Backend** | Django 6.0 + Django REST Framework | REST API, scoring engine, database models |
| **Frontend** | Next.js 14 (App Router, TypeScript/TSX) | Glassmorphic UI with TailwindCSS |
| **Database** | PostgreSQL (primary) / SQLite (fallback) | Auto-fallback if `psycopg2` is not installed |
| **CLI** | Node.js (ES Modules) | Interactive terminal scanner |
| **Extension** | Chrome Extension (Manifest V3) | Background service worker + warning page |

---

## 📦 Project Structure

```
Phishing_Website_Detector/
│
├── backend/                          # Django backend
│   ├── phishing_backend/             # Django project settings
│   │   ├── settings.py               # DB config, CORS, installed apps
│   │   ├── urls.py                   # Root URL routing → /api/
│   │   └── wsgi.py                   # WSGI entry point
│   ├── analyzer/                     # Core analysis app
│   │   ├── models.py                 # ScanHistory, DomainPolicy models
│   │   ├── views.py                  # API views (AnalyzeURL, History, Policy)
│   │   ├── services.py               # Heuristic engine + vendor integrations
│   │   ├── serializers.py            # DRF serializers
│   │   └── urls.py                   # /api/analyze, /api/history, /api/policy
│   ├── run.py                        # Django management script (renamed from manage.py)
│   └── .env                          # ⚠️ Environment variables (NOT committed)
│
├── frontend/                         # Next.js frontend
│   ├── src/
│   │   ├── app/                      # App Router
│   │   │   ├── layout.tsx            # Root layout
│   │   │   ├── page.tsx              # Main scanner page
│   │   │   └── globals.css           # Global styles
│   │   └── components/               # Reusable UI components
│   │       ├── ScannerInput.tsx       # URL input form
│   │       ├── VerdictCard.tsx        # Score + verdict display
│   │       ├── HeuristicsTab.tsx      # Detailed heuristic breakdown
│   │       ├── ApiFeedsTab.tsx        # External API results tab
│   │       ├── PolicyManager.tsx      # Whitelist/Blacklist manager
│   │       └── ScanHistoryLog.tsx     # Scan history viewer
│   ├── package.json
│   └── next.config.js
│
├── extension/                        # Chrome Extension (Manifest V3)
│   ├── manifest.json                 # Extension config
│   ├── background.js                 # Service worker — intercepts navigation
│   ├── warning.html                  # Phishing warning interstitial page
│   └── icon.png                      # Extension icon
│
├── index.js                          # CLI scanner (Node.js)
├── package.json                      # Root package.json for CLI
├── .gitignore
└── README.md
```

---

## 🔑 Required API Keys

This project integrates with **4 external security APIs**. You need to obtain free API keys from each:

| # | Service | Purpose | Get Your Key |
|---|---------|---------|--------------|
| 1 | **Google Safe Browsing** | Checks URLs against Google's threat database | [Google Cloud Console](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) |
| 2 | **VirusTotal** | Aggregates 70+ antivirus engine results for a URL | [VirusTotal API](https://www.virustotal.com/gui/join-us) |
| 3 | **IPQualityScore** | Returns risk score, phishing/malware/suspicious flags | [IPQS Dashboard](https://www.ipqualityscore.com/create-account) |
| 4 | **URLScan.io** | Submits URLs for deep scanning and screenshots | [URLScan API](https://urlscan.io/user/signup) |

> **All four APIs offer free tiers** that are sufficient for development and moderate usage.

---

## ⚙️ Environment Variables

Create a file at **`backend/.env`** with the following variables:

```env
# Django configuration
DEBUG=True
SECRET_KEY=your-secret-key-change-in-production

# Database Configuration (leave DB_PASSWORD empty to fall back to SQLite)
DB_NAME=phishing_db
DB_USER=postgres
DB_PASSWORD=
DB_HOST=127.0.0.1
DB_PORT=5432

# External Service API Keys (REQUIRED)
GOOGLE_SAFE_BROWSING_API_KEY=your_google_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
IPQUALITYSCORE_API_KEY=your_ipqs_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here
```

> ⚠️ **This file is in `.gitignore` and must NEVER be committed to Git.** It contains sensitive API keys.

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.11+** (with `pip`)
- **Node.js 20+** (with `npm`)
- **PostgreSQL** (optional — SQLite works out of the box)
- **Git**

### 1. Clone the Repository

```bash
git clone https://github.com/PraveenChigurla/Phishing_Website_Detector.git
cd Phishing_Website_Detector
```

### 2. Backend Setup

```bash
# Create and activate a virtual environment
python -m venv venv

# Windows
.\venv\Scripts\Activate.ps1
# macOS/Linux
source venv/bin/activate

# Install Python dependencies
pip install -r backend/requirements.txt

# Create the environment file
cp backend/.env.example backend/.env
# ✏️ Edit backend/.env and add your API keys

# Run database migrations
python backend/run.py migrate

# Start the Django development server
python backend/run.py runserver 8000
```

The API is now live at **`http://127.0.0.1:8000/api/`**

### 3. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

The UI is now live at **`http://localhost:3000`**

### 4. CLI Scanner (Optional)

```bash
# From the project root
npm install
node index.js
```

### 5. Chrome Extension (Optional)

1. Open `chrome://extensions/` in Chrome.
2. Enable **Developer mode** (top-right toggle).
3. Click **Load unpacked** → select the `extension/` folder.
4. The extension icon appears in your toolbar — it auto-scans every URL you visit.

---

## 📡 API Endpoints

All endpoints are prefixed with `/api/`.

| Method | Endpoint | Description | Body |
|--------|----------|-------------|------|
| `POST` | `/api/analyze` | Scan a URL and return verdict | `{ "url": "https://example.com" }` |
| `GET` | `/api/history` | List all past scans (paginated) | — |
| `GET` | `/api/policy` | List whitelist/blacklist rules | — |
| `POST` | `/api/policy` | Add a whitelist/blacklist rule | `{ "domain": "example.com", "policy": "whitelist", "reason": "..." }` |
| `POST` | `/api/urlscan` | Proxy scan to URLScan.io | `{ "url": "https://example.com" }` |
| `GET` | `/api/ipquality?url=...` | Proxy scan to IPQualityScore | Query param: `url` |

### Example Response (`POST /api/analyze`)

```json
{
  "Verdict": "SAFE",
  "Final Score": 6.0,
  "HeuristicReasons": [],
  "Votes": {
    "phishing": 0,
    "suspicious": 0,
    "legit": 4,
    "uncertain": 0
  },
  "GoogleSafeBrowsing": { "status": "legit", "message": "No threats found." },
  "VirusTotal": { "status": "legit", "message": "Only 0 malicious detections out of 93." },
  "IPQualityScore": { "status": "legit", "message": "Risk score: 0" },
  "Lexical": [ 3.0, { "url_length": 28, "has_ip": false, "..." : "..." } ],
  "WHOIS": [ 1, { "domain_age_days": 3650, "whois_success": true } ],
  "SSL": [ 1, { "ssl_status": "Valid" } ]
}
```

---

## 🧠 How the Scoring Engine Works

### Heuristic Signals (15+ features)

| Category | Signals Checked |
|----------|-----------------|
| **Lexical** | URL length, IP address in URL, `@` symbol, hex encoding, non-standard port, subdomain count, URL entropy, path depth |
| **Keyword** | Phishing-related words in URL *(weak signal, only −0.5 penalty)* |
| **WHOIS** | Domain age, registrar presence, RDAP fallback |
| **SSL** | Certificate validity (Valid / Invalid / HTTP-only) |
| **JavaScript** | Suspicious scripts (keyloggers, obfuscated eval, credential exfiltration) |
| **HTML** | Password fields with external form actions, hidden iframes, external favicons |
| **Free Hosting** | Detection of free platforms (vercel.app, netlify.app, github.io, etc.) |

### Verdict Decision Rules

```
Rule 1: If ALL external APIs say "legit"           → SAFE   (vendor consensus wins)
Rule 2: If 2+ APIs say "legit" & none say phishing → SAFE
Rule 3: If Google Safe Browsing flags phishing      → PHISHING (authoritative)
Rule 4: If 2+ sources say phishing                  → PHISHING
Rule 5: If 1 phishing vote or 2+ suspicious         → SUSPICIOUS
Rule 6: Heuristic suspicious + all APIs uncertain   → SUSPICIOUS
Else:                                                → SAFE
```

### Score Ranges

| Score | Verdict |
|-------|---------|
| 0.0 – 3.5 | 🔴 **PHISHING** |
| 3.6 – 5.5 | 🟡 **SUSPICIOUS** |
| 5.6 – 10.0 | 🟢 **SAFE** |

---

## 🧪 Testing

### Test URLs

| URL | Expected Verdict | Why |
|-----|------------------|-----|
| `https://www.facebook.com` | ✅ SAFE | Well-known domain, all APIs confirm |
| `https://checkphish.bolster.ai` | ✅ SAFE | Legitimate security company, vendor consensus overrides keyword |
| `https://phishing-website-flax.vercel.app` | ⚠️ SUSPICIOUS | Free hosting + suspicious keyword + IPQS flags it |

### Run Tests

```bash
python backend/run.py test
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Follow coding standards: **PEP 8** (Python), **ESLint/Prettier** (TSX)
4. Submit a Pull Request with a clear description

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Praveen Chigurla** — [GitHub](https://github.com/PraveenChigurla)
