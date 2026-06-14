import os
import re
import math
import ssl
import socket
import datetime
import logging
import base64
import requests
from urllib.parse import urlparse
from collections import Counter
from bs4 import BeautifulSoup
from django.conf import settings
from .models import ScanHistory, DomainPolicy

logger = logging.getLogger(__name__)

# Attempt to load whois library
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


# ---------------------------------------------------------------------------- #
#  Heuristic Utilities                                                          #
# ---------------------------------------------------------------------------- #

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [n_x / len(s) for x, n_x in Counter(s).items()]
    return -sum(p * math.log2(p) for p in prob)


def fallback_rdap(domain: str) -> dict:
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.warning(f"RDAP Fallback failed for {domain}: {e}")
    return {}


# ---------------------------------------------------------------------------- #
#  Feature Extractors                                                           #
# ---------------------------------------------------------------------------- #

def check_ssl_certificate(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        if parsed.scheme != 'https':
            return "Invalid (HTTP)"
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return "Valid" if cert else "Invalid"
    except Exception as e:
        logger.warning(f"SSL check failed for {url}: {e}")
        return "Error"


def check_suspicious_js(url: str) -> dict:
    try:
        response = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = soup.find_all("script")
        suspicious = False
        details = []

        SUSPICIOUS_PATTERNS = ["eval(", "document.write", "unescape(", "atob(", "fromCharCode"]
        for script in scripts:
            if script.string:
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in script.string:
                        suspicious = True
                        details.append(f"{pattern} usage detected")

        # Also scan inline event handlers
        for tag in soup.find_all(True):
            for attr in ["onclick", "onload", "onerror"]:
                val = tag.get(attr, "")
                if "eval(" in val or "unescape(" in val:
                    suspicious = True
                    details.append(f"Inline {attr} with obfuscation")

        return {
            "suspicious_scripts": suspicious,
            "details": list(set(details)),
            "has_error": False
        }
    except Exception as e:
        logger.warning(f"JS behavior scan failed for {url}: {e}")
        return {
            "suspicious_scripts": False,
            "details": [f"Error connecting to website: {str(e)}"],
            "has_error": True
        }


def check_html_content(url: str) -> dict:
    """
    Analyses the fetched HTML for phishing indicators:
    - Login forms with suspicious action targets
    - Password fields present
    - Hidden redirect / iframe injections
    - Favicon loaded from an external (different) domain
    Returns a score delta (+1 clean, -1 suspicious) and detail dict.
    """
    result = {
        "has_password_field": False,
        "external_form_action": False,
        "hidden_iframe": False,
        "external_favicon": False,
        "details": [],
        "has_error": False,
    }
    try:
        response = requests.get(url, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
        soup = BeautifulSoup(response.text, "html.parser")
        parsed = urlparse(url)
        base_domain = parsed.netloc

        # Password fields
        if soup.find("input", {"type": "password"}):
            result["has_password_field"] = True
            result["details"].append("Password input field found")

        # External form action
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action.startswith("http") and base_domain not in action:
                result["external_form_action"] = True
                result["details"].append(f"External form action: {action[:80]}")

        # Hidden iframes
        for iframe in soup.find_all("iframe"):
            style = iframe.get("style", "").replace(" ", "").lower()
            if "display:none" in style or "visibility:hidden" in style or \
               (iframe.get("width") in ["0", "1"] and iframe.get("height") in ["0", "1"]):
                result["hidden_iframe"] = True
                result["details"].append("Hidden iframe detected")

        # External favicon
        for link in soup.find_all("link", rel=lambda r: r and "icon" in r):
            href = link.get("href", "")
            if href.startswith("http") and base_domain not in href:
                result["external_favicon"] = True
                result["details"].append(f"External favicon: {href[:80]}")

    except Exception as e:
        logger.warning(f"HTML content check failed for {url}: {e}")
        result["has_error"] = True
        result["details"].append(f"Error: {str(e)}")

    return result


# Known free-hosting platforms that are commonly abused for phishing
FREE_HOSTING_PLATFORMS = [
    "vercel.app", "github.io", "netlify.app", "pages.dev",
    "firebaseapp.com", "web.app", "herokuapp.com", "weebly.com",
    "wixsite.com", "000webhostapp.com", "glitch.me", "repl.co",
    "surge.sh", "render.com", "fly.dev", "onrender.com",
    "workers.dev", "azurewebsites.net", "appspot.com",
]

PHISHING_KEYWORDS = [
    "login", "verify", "update", "bank", "secure", "account", "signin",
    "sign-in", "webscr", "confirm", "submit", "free", "paypal", "amazon",
    "support", "security", "ebay", "password", "unlock", "validation",
    "reset", "recovery", "phish", "phishing", "credential", "wallet",
    "invoice", "urgent", "suspended", "verify", "authenticate",
]


def check_free_hosting(url: str) -> dict:
    """
    Manually parse hostname to detect free-hosting platforms.
    `tld` library doesn't know compound suffixes like `vercel.app`,
    so we match via simple suffix string comparison.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    hostname_lower = hostname.lower()

    matched_platform = None
    for platform in FREE_HOSTING_PLATFORMS:
        if hostname_lower == platform or hostname_lower.endswith("." + platform):
            matched_platform = platform
            break

    if not matched_platform:
        return {
            "is_free_hosting": False,
            "platform": "",
            "subdomain": "",
            "contains_suspicious_keywords": False,
        }

    # Extract the subdomain (everything before the platform suffix)
    subdomain = hostname_lower[: len(hostname_lower) - len(matched_platform)].rstrip(".")

    contains_suspicious = any(kw in subdomain for kw in PHISHING_KEYWORDS)

    return {
        "is_free_hosting": True,
        "platform": matched_platform,
        "subdomain": subdomain,
        "contains_suspicious_keywords": contains_suspicious,
    }


def extract_lexical_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    full_url_lower = url.lower()

    subdomains = hostname.split('.')
    num_subdomains = max(0, len(subdomains) - 2) if hostname else 0

    has_suspicious_words = any(word in full_url_lower for word in PHISHING_KEYWORDS)

    features = {
        "url_length": len(url),
        "num_dots": url.count('.'),
        "num_subdomains": num_subdomains,
        "has_ip": bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)),
        "has_at_symbol": "@" in url,
        "has_hex_encoding": '%' in url,
        "has_suspicious_words": has_suspicious_words,
        "non_standard_port": bool(parsed.port and parsed.port not in [80, 443]),
        "url_entropy": shannon_entropy(url),
        "url_depth": len([p for p in parsed.path.split('/') if p]),
    }
    return features


def get_domain_info(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age_days = None
            if isinstance(creation_date, datetime.datetime):
                age_days = (datetime.datetime.utcnow() - creation_date.replace(tzinfo=None)).days

            return {
                "domain_age_days": age_days,
                "has_registrar": bool(w.registrar),
                "whois_success": True,
            }
        except Exception as e:
            logger.warning(f"Python whois failed for {domain}: {e}")

    # Fallback to RDAP
    rdap = fallback_rdap(domain)
    if rdap:
        events = rdap.get("events", [])
        registration = next((e for e in events if e.get("eventAction") == "registration"), None)
        age_days = None
        if registration:
            try:
                reg_date = datetime.datetime.fromisoformat(registration["eventDate"].replace("Z", "+00:00"))
                age_days = (datetime.datetime.now(datetime.timezone.utc) - reg_date).days
            except Exception:
                pass
        return {
            "domain_age_days": age_days,
            "has_registrar": True,
            "whois_success": True,
            "note": "Fetched via RDAP fallback",
        }

    return {
        "domain_age_days": None,
        "has_registrar": False,
        "whois_success": False,
    }


# ---------------------------------------------------------------------------- #
#  Third-Party Scan Integrations                                                #
# ---------------------------------------------------------------------------- #

def scan_with_google_safe_browsing(url: str) -> dict:
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return {"success": False, "status": "uncertain", "message": "API key missing"}

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishing-backend", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        response = requests.post(api_url, json=payload, timeout=8)
        if response.status_code == 200:
            result = response.json()
            is_safe = "matches" not in result
            return {
                "success": True,
                "status": "legit" if is_safe else "phishing",
                "message": "No threats found." if is_safe else f"Threats detected: {result['matches']}",
            }
        return {"success": False, "status": "uncertain", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"Google Safe Browsing API error: {e}")
        return {"success": False, "status": "uncertain", "message": str(e)}


def scan_with_virustotal(url: str) -> dict:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return {"success": False, "status": "uncertain", "message": "API key missing"}

    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().replace('=', '')
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(api_url, headers=headers, timeout=8)
        if response.status_code == 200:
            data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious_vt = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + harmless + suspicious_vt + undetected

            if malicious >= 2:
                return {
                    "success": True,
                    "status": "phishing",
                    "message": f"{malicious}/{total} engines flagged as malicious.",
                    "malicious_count": malicious,
                }
            if suspicious_vt >= 2:
                return {
                    "success": True,
                    "status": "suspicious",
                    "message": f"{suspicious_vt}/{total} engines flagged as suspicious.",
                    "malicious_count": suspicious_vt,
                }
            return {
                "success": True,
                "status": "legit",
                "message": f"Only {malicious} malicious detections out of {total}.",
                "malicious_count": malicious,
            }

        elif response.status_code == 404:
            # Submit for scanning
            submit_url = "https://www.virustotal.com/api/v3/urls"
            requests.post(submit_url, headers=headers, data={"url": url}, timeout=5)
            return {
                "success": False,
                "status": "uncertain",
                "message": "URL not in VirusTotal cache. Submitted for analysis — retry in 60 s.",
            }
        return {"success": False, "status": "uncertain", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"VirusTotal API error: {e}")
        return {"success": False, "status": "uncertain", "message": str(e)}


def scan_with_ipqualityscore(url: str) -> dict:
    api_key = os.environ.get("IPQUALITYSCORE_API_KEY", "")
    if not api_key:
        return {"success": False, "status": "uncertain", "message": "API key missing"}

    encoded = requests.utils.quote(url, safe="")
    api_url = f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded}?strictness=2&fast=1"
    try:
        response = requests.get(api_url, timeout=8)
        if response.status_code == 200:
            result = response.json()
            if not result.get("success", False):
                return {"success": False, "status": "uncertain", "message": result.get("message", "Unknown error")}

            risk_score = result.get("risk_score", 0)
            phishing_flag = result.get("phishing", False)
            suspicious_flag = result.get("suspicious", False)
            malware_flag = result.get("malware", False)

            if phishing_flag or malware_flag or risk_score >= 75:
                status_str = "phishing"
            elif suspicious_flag or risk_score >= 50:
                status_str = "suspicious"
            else:
                status_str = "legit"

            return {
                "success": True,
                "status": status_str,
                "message": f"Risk Score: {risk_score}/100 — Phishing: {phishing_flag}, Suspicious: {suspicious_flag}",
                "risk_score": risk_score,
            }
        return {"success": False, "status": "uncertain", "message": f"HTTP {response.status_code}"}
    except Exception as e:
        logger.error(f"IPQS API error: {e}")
        return {"success": False, "status": "uncertain", "message": str(e)}


def scan_with_urlscan(url: str) -> dict:
    api_key = os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        return {"success": False, "status": "uncertain", "message": "API key missing"}

    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    payload = {"url": url, "visibility": "public"}
    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=8)
        if response.status_code in (200, 201):
            return {
                "success": True,
                "status": "legit",
                "message": "Scan successfully submitted to URLScan.",
            }
        return {"success": False, "status": "uncertain", "message": f"HTTP {response.status_code}: {response.text[:200]}"}
    except Exception as e:
        logger.error(f"URLScan API error: {e}")
        return {"success": False, "status": "uncertain", "message": str(e)}


# ---------------------------------------------------------------------------- #
#  Heuristic Scoring Engine                                                     #
# ---------------------------------------------------------------------------- #

def _compute_heuristic_score(lexical: dict, whois_data: dict, ssl_status: str,
                               js_behavior: dict, html_data: dict, free_hosting: dict) -> tuple[float, list[str]]:
    """
    Returns (raw_score, list_of_reasons).
    Score is unbounded; caller normalises to 0–10 and maps to verdict.
    Positive = safer, Negative = more suspicious.
    """
    score = 0.0
    reasons = []

    # ── Lexical features ──────────────────────────────────────────────────────
    url_length = lexical["url_length"]
    if url_length < 54:
        score += 1.5
    elif url_length < 75:
        score += 0.5
    elif url_length < 100:
        score -= 0.5
    else:
        score -= 1.5
        reasons.append(f"Very long URL ({url_length} chars)")

    if lexical["has_ip"]:
        score -= 2.0
        reasons.append("URL contains raw IP address")

    if lexical["has_at_symbol"]:
        score -= 2.0
        reasons.append("URL contains @ symbol")

    if lexical["has_hex_encoding"]:
        score -= 1.0
        reasons.append("URL contains hex encoding")

    if lexical["non_standard_port"]:
        score -= 1.5
        reasons.append("Non-standard port in URL")

    if lexical["has_suspicious_words"]:
        score -= 0.5
        reasons.append("URL contains phishing-related keywords (weak signal)")

    num_sub = lexical["num_subdomains"]
    if num_sub == 0:
        score += 1.0
    elif num_sub == 1:
        score += 0.5
    elif num_sub == 2:
        score -= 0.5
    else:
        score -= 1.5
        reasons.append(f"Excessive subdomains ({num_sub})")

    entropy = lexical["url_entropy"]
    if entropy > 4.5:
        score -= 1.5
        reasons.append(f"High URL entropy ({entropy:.2f}) — possible obfuscation")
    elif entropy > 4.2:
        score -= 0.5

    url_depth = lexical.get("url_depth", 0)
    if url_depth > 5:
        score -= 1.0
        reasons.append(f"Deep URL path depth ({url_depth})")

    # ── WHOIS / Domain age ────────────────────────────────────────────────────
    if whois_data["whois_success"]:
        age = whois_data.get("domain_age_days")
        if age is not None:
            if age < 30:
                score -= 3.0
                reasons.append(f"Domain is very new ({age} days old)")
            elif age < 90:
                score -= 1.5
                reasons.append(f"Domain is recent ({age} days old)")
            elif age < 365:
                score -= 0.5
            elif age >= 365:
                score += 1.5
                if age >= 730:
                    score += 0.5  # Extra bonus for 2+ year old domains
        if whois_data["has_registrar"]:
            score += 0.5
    else:
        score -= 0.5
        reasons.append("WHOIS lookup failed — domain info unavailable")

    # ── SSL certificate ───────────────────────────────────────────────────────
    if ssl_status == "Valid":
        score += 0.5
    elif ssl_status == "Invalid (HTTP)":
        score -= 2.0
        reasons.append("Site uses plain HTTP (no SSL)")
    elif ssl_status in ("Invalid", "Error"):
        score -= 1.5
        reasons.append(f"SSL certificate issue: {ssl_status}")

    # ── JavaScript behaviour ──────────────────────────────────────────────────
    if js_behavior.get("suspicious_scripts"):
        score -= 2.0
        reasons.append("Suspicious JavaScript detected: " + ", ".join(js_behavior.get("details", [])))
    elif not js_behavior.get("has_error"):
        score += 0.5

    # ── HTML content ──────────────────────────────────────────────────────────
    if not html_data.get("has_error"):
        if html_data.get("has_password_field") and html_data.get("external_form_action"):
            score -= 3.0
            reasons.append("Password field submitting to external domain")
        elif html_data.get("has_password_field"):
            score -= 0.5  # Could be legit login page
        if html_data.get("hidden_iframe"):
            score -= 2.0
            reasons.append("Hidden iframe detected")
        if html_data.get("external_favicon"):
            score -= 0.5
            reasons.append("Favicon loaded from external domain")

    # ── Free hosting platform ─────────────────────────────────────────────────
    if free_hosting["is_free_hosting"]:
        if free_hosting["contains_suspicious_keywords"]:
            score -= 2.0
            reasons.append(
                f"Suspicious keyword '{free_hosting['subdomain']}' on free hosting '{free_hosting['platform']}'"
            )
        else:
            score -= 0.5
            reasons.append(f"Hosted on free platform: {free_hosting['platform']}")

    return score, reasons


# ---------------------------------------------------------------------------- #
#  Core Orchestrator                                                            #
# ---------------------------------------------------------------------------- #

def analyze_url_service(url: str) -> dict:
    # Normalise URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]

    # 1. Local whitelist / blacklist overrides
    policy_match = DomainPolicy.objects.filter(domain=domain).first()
    if policy_match:
        if policy_match.policy == 'whitelist':
            return {
                "Verdict": "SAFE",
                "Final Score": 10.0,
                "PolicyOverride": True,
                "Reason": f"Whitelisted domain: {policy_match.reason or 'No reason provided'}",
            }
        elif policy_match.policy == 'blacklist':
            return {
                "Verdict": "PHISHING",
                "Final Score": 0.0,
                "PolicyOverride": True,
                "Reason": f"Blacklisted domain: {policy_match.reason or 'No reason provided'}",
            }

    # 2. Feature extraction
    lexical = extract_lexical_features(url)
    whois_data = get_domain_info(url)
    ssl_status = check_ssl_certificate(url)
    js_behavior = check_suspicious_js(url)
    html_data = check_html_content(url)
    free_hosting = check_free_hosting(url)

    # 3. Heuristic scoring
    raw_score, heuristic_reasons = _compute_heuristic_score(
        lexical, whois_data, ssl_status, js_behavior, html_data, free_hosting
    )

    # Normalise raw score → 0–10 scale
    # Raw score typically ranges from ~-15 (very suspicious) to ~+10 (very safe).
    # Map: raw >= 8 → 10/10 safe, raw <= -10 → 0/10 phishing.
    normalised = max(0.0, min(10.0, (raw_score + 10) * (10 / 20)))
    normalised = round(normalised, 2)

    if normalised <= 3.5:
        heuristic_verdict = "PHISHING"
    elif normalised <= 5.5:
        heuristic_verdict = "SUSPICIOUS"
    else:
        heuristic_verdict = "SAFE"

    # 4. External threat intelligence
    gsb = scan_with_google_safe_browsing(url)
    vt = scan_with_virustotal(url)
    ipqs = scan_with_ipqualityscore(url)

    # 5. Aggregated decision engine
    #    External vendor verdicts are the PRIMARY signal.
    #    Heuristics are a SUPPORTING signal — they can escalate suspicion
    #    but cannot override unanimous vendor consensus.
    api_phishing = 0
    api_suspicious = 0
    api_legit = 0
    api_uncertain = 0

    for svc in [gsb, vt, ipqs]:
        s = svc.get("status", "uncertain")
        if s == "phishing":
            api_phishing += 1
        elif s == "suspicious":
            api_suspicious += 1
        elif s == "legit":
            api_legit += 1
        else:
            api_uncertain += 1

    # Build total votes (APIs = 1 vote each, heuristic = 1 vote)
    phishing_votes = api_phishing
    suspicious_votes = api_suspicious
    legit_votes = api_legit
    uncertain_votes = api_uncertain

    if heuristic_verdict == "PHISHING":
        phishing_votes += 1
    elif heuristic_verdict == "SUSPICIOUS":
        suspicious_votes += 1
    else:
        legit_votes += 1

    # ── Final verdict logic ───────────────────────────────────────────────
    # Rule 1: If ALL responding external APIs agree legit → SAFE
    #         (heuristic keywords alone cannot override vendor consensus)
    if api_legit >= 3:
        verdict = "SAFE"
    # Rule 2: If ALL responding external APIs agree legit (2/2) and the
    #         third is uncertain, still trust the vendors
    elif api_legit >= 2 and api_phishing == 0:
        verdict = "SAFE"
    # Rule 3: Google Safe Browsing is authoritative — if it flags phishing,
    #         that alone is enough
    elif gsb.get("status") == "phishing":
        verdict = "PHISHING"
    # Rule 4: 2+ sources (API or heuristic) say phishing
    elif phishing_votes >= 2:
        verdict = "PHISHING"
    # Rule 5: Mixed signals — some phishing or many suspicious
    elif phishing_votes >= 1 or suspicious_votes >= 2:
        verdict = "SUSPICIOUS"
    # Rule 6: Heuristic alone is suspicious but all APIs are uncertain
    elif heuristic_verdict != "SAFE" and api_uncertain >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    # Blend final display score: heuristic score influences display score
    # If external APIs flag as phishing, push score down; if safe, keep normalised
    if verdict == "PHISHING":
        display_score = min(normalised, 3.5)
    elif verdict == "SUSPICIOUS":
        display_score = min(max(normalised, 3.6), 5.5)
    else:
        display_score = max(normalised, 5.6) if normalised < 5.6 else normalised

    display_score = round(display_score, 2)

    report = {
        "Lexical": (round(raw_score, 2), lexical),
        "WHOIS": (1 if whois_data["whois_success"] else -1, whois_data),
        "HTML": (1 if not html_data.get("has_error") else 0, html_data),
        "JavaScript": (-1 if js_behavior.get("suspicious_scripts") else 1, js_behavior),
        "SSL": (1 if ssl_status == "Valid" else -1, {"ssl_status": ssl_status}),
        "FreeHosting": free_hosting,
        "HeuristicReasons": heuristic_reasons,
        "GoogleSafeBrowsing": gsb,
        "VirusTotal": vt,
        "IPQualityScore": ipqs,
        "Votes": {
            "phishing": phishing_votes,
            "suspicious": suspicious_votes,
            "legit": legit_votes,
            "uncertain": uncertain_votes,
        },
        "Final Score": display_score,
        "Verdict": verdict,
    }

    # 6. Persist to ScanHistory
    try:
        ScanHistory.objects.create(
            url=url,
            final_score=display_score,
            verdict=verdict,
            details=report,
        )
    except Exception as db_err:
        logger.error(f"Failed to save scan history: {db_err}")

    return report
