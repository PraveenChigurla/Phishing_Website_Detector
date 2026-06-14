# Phishing Detection with Extension 🚀
A modern full‑stack phishing‑url detection system built with Django, Next.js (TSX) and PostgreSQL.
## ✨ Overview

**Phishing Detection with Extension** is a modern, full‑stack application that scans URLs for phishing threats using a **weighted heuristic engine** combined with **real‑time intelligence from three security vendors** (Google Safe Browsing, VirusTotal, and IPQualityScore).  It provides:
- A **Django REST API** backend (PostgreSQL support, fallback to SQLite).
- A **Next.js (App Router) TSX** frontend with a sleek, glass‑morphic UI.
- **Dynamic scoring** that respects vendor consensus over noisy keyword heuristics, drastically reducing false‑positives (e.g., `checkphish.bolster.ai`).
- Deployment‑ready Docker configuration and a **CLI client** for quick testing.

The project follows the tech‑stack preferences you requested: **Django**, **Next.js (TSX)**, **PostgreSQL**.

---

## 🛠️ Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Backend | Django | 6.0.4 |
| Database | PostgreSQL (or SQLite for quick dev) | N/A |
| Frontend | Next.js (App Router) with TypeScript (TSX) | 14.x |
| Styling | TailwindCSS (custom theme) + Glassmorphism | 3.3 |
| CLI | Node.js script (`index.js`) | 20.x |
| Scoring Engine | Custom Python module (`services.py`) | – |

---

## 📦 Project Structure (clean & organized)

```
Phishing_Detection_with_Extension/
│
├─ backend/                     # Django project
│   ├─ phishing_backend/        # Settings, URLs, WSGI
│   ├─ analyzer/               # Core scoring logic
│   │   └─ services.py          # Heuristic + vendor aggregation
│   ├─ run.py                  # Entry point (renamed from manage.py)
│   └─ requirements.txt        # Python deps
│
├─ frontend/                    # Next.js app
│   ├─ src/
│   │   ├─ app/               # App Router pages (page.tsx, etc.)
│   │   └─ components/        # UI components (HeuristicsTab.tsx, etc.)
│   ├─ next.config.js
│   └─ package.json
│
├─ index.js                     # CLI driver for quick URL checks
├─ .env                         # Environment variables (API keys, DB URL)
├─ README.md                    # <‑‑ you are reading this!
└─ Dockerfile / docker-compose.yml (optional)
```

---

## 🚀 Getting Started (Windows)

### 1️⃣ Prerequisites

- **Python 3.11+** (add to `PATH`).
- **Node.js 20+** and **npm**.
- **PostgreSQL** (optional – SQLite works out‑of‑the‑box).
- **Git** (for cloning the repo).

### 2️⃣ Clone the Repository

```powershell
git clone https://github.com/PraveenChigurla/Phishing_Website_Detector.git
cd Phishing_Website_Detector  
```

### 3️⃣ Backend Setup

```powershell
# Create a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r backend\requirements.txt

# Set up environment variables (copy .env.example → .env)
copy .env.example .env
# Edit .env to add your API keys and DB URL

# Initialise the DB (SQLite fallback works)
python backend\run.py migrate

# Run the development server
python backend\run.py runserver 8000
```

The API is now reachable at `http://127.0.0.1:8000/api/scan/`.

### 4️⃣ Frontend Setup

```powershell
cd frontend
npm install
npm run dev   # Starts Next.js at http://localhost:3000
```

### 5️⃣ CLI Quick Test

```powershell
node index.js   # Prompts for a URL and prints the verdict
```

---

## 📡 API End‑point

**POST** `/api/scan/`
```json
{ "url": "https://example.com" }
```
**Response** (pretty‑printed):
```json
{
  "Verdict": "SAFE",
  "Final Score": 6.1,
  "HeuristicReasons": ["URL contains phishing-related keywords (weak signal)"],
  "Votes": {"phishing":0,"suspicious":0,"legit":4,"uncertain":0},
  "GoogleSafeBrowsing": {"status":"legit"},
  "VirusTotal": {"status":"legit"},
  "IPQualityScore": {"status":"legit"}
}
```
The engine follows the **vendor‑consensus priority** described in the code comments.

---

## 🎨 UI Highlights

> ![UI screenshot](file:///C:/Users/hp/.gemini/antigravity-ide/brain/71922486-792b-4c1d-89aa-c653b56f92e0/media__1781438776998.png)

The interface uses a glass‑morphic card with subtle micro‑animations, showing:
- URL input box.
- Real‑time scoring bar (0‑10).
- Detailed breakdown of heuristic reasons and vendor votes.

---

## 🧪 Testing & Verification

1. **Run the Django test suite** (if you add tests later):
   ```powershell
   python backend\run.py test
   ```
2. **Manual verification** – open the frontend, try:
   - `https://checkphish.bolster.ai` (should be **SAFE**).
   - `https://phishing-website-flax.vercel.app` (should be **SUSPICIOUS**).
   - `https://www.facebook.com` (should be **SAFE**).

---

## 🤝 Contributing

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/awesome`).
3. Follow the coding style (PEP‑8 for Python, ESLint/Prettier for TSX).
4. Submit a Pull Request with a clear description and screenshots.

Please keep the **heuristic weighting** consistent with the design notes in `services.py`.

---

## 📄 License

MIT License – feel free to use, modify, and distribute.

---

**Happy hunting!** 🎯
