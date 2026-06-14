const API_URL = 'http://127.0.0.1:8000';
const urlInput = document.getElementById('urlInput');
const scanBtn = document.getElementById('scanBtn');
const resultCard = document.getElementById('resultCard');
const errorMsg = document.getElementById('errorMsg');
const statusDot = document.getElementById('statusDot');

// Auto-fill current tab URL
if (typeof chrome !== 'undefined' && chrome.tabs) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    try {
      if (tabs && tabs.length > 0 && tabs[0]?.url) {
        const url = tabs[0].url;
        if (!url.startsWith('chrome://') && !url.startsWith('chrome-extension://')) {
          urlInput.value = url;
          // Automatically trigger scan for the current tab
          scanBtn.click();
        }
      }
    } catch (e) {
      console.error("Tab query error:", e);
    }
  });
}

// Check backend health
async function checkBackend() {
  try {
    const r = await fetch(API_URL + '/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://healthcheck.internal' }),
      signal: AbortSignal.timeout(3000),
    });
    if (r.ok) {
      statusDot.classList.remove('offline');
      statusDot.title = 'Backend: Online';
    } else {
      statusDot.classList.add('offline');
      statusDot.title = 'Backend: Offline';
    }
  } catch {
    statusDot.classList.add('offline');
    statusDot.title = 'Backend: Offline';
  }
}
checkBackend();

// Scan
scanBtn.addEventListener('click', async () => {
  const url = urlInput.value.trim();
  if (!url) { urlInput.focus(); return; }

  resultCard.classList.add('hidden');
  errorMsg.classList.add('hidden');

  // Show loading state
  scanBtn.disabled = true;
  scanBtn.innerHTML = '<div class="spinner"></div> Scanning...';

  // Check chrome.storage.local cache first
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    try {
      const cached = await new Promise((resolve) => {
        chrome.storage.local.get([url], (res) => resolve(res ? res[url] : null));
      });

      if (cached && cached.verdict && cached.verdict !== 'PENDING' && cached.data) {
        // If result is fresh (under 5 minutes old), render immediately
        const fiveMinutes = 5 * 60 * 1000;
        if (Date.now() - cached.timestamp < fiveMinutes) {
          console.log("Using cached scan result for popup");
          renderResult(cached.data);
          scanBtn.disabled = false;
          scanBtn.innerHTML = `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Scan`;
          return;
        }
      }
    } catch (cacheErr) {
      console.warn("Cache read error:", cacheErr);
    }
  }

  try {
    const resp = await fetch(API_URL + '/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    renderResult(data);
  } catch (err) {
    errorMsg.textContent = '⚠ Backend error: ' + err.message;
    errorMsg.classList.remove('hidden');
  } finally {
    scanBtn.disabled = false;
    scanBtn.innerHTML = `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:14px;height:14px"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg> Scan`;
  }
});

// Enter key triggers scan
urlInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') scanBtn.click();
});

// Tab elements
const tabBtnFeeds = document.getElementById('tabBtnFeeds');
const tabBtnHeuristics = document.getElementById('tabBtnHeuristics');
const tabContentFeeds = document.getElementById('tabContentFeeds');
const tabContentHeuristics = document.getElementById('tabContentHeuristics');

// Tab Switching
tabBtnFeeds.addEventListener('click', () => {
  tabBtnFeeds.classList.add('active');
  tabBtnHeuristics.classList.remove('active');
  tabContentFeeds.classList.remove('hidden');
  tabContentHeuristics.classList.add('hidden');
});

tabBtnHeuristics.addEventListener('click', () => {
  tabBtnHeuristics.classList.add('active');
  tabBtnFeeds.classList.remove('active');
  tabContentHeuristics.classList.remove('hidden');
  tabContentFeeds.classList.add('hidden');
});

function renderResult(data) {
  const verdict = (data.Verdict || 'SAFE').toUpperCase();
  const score = data['Final Score'] || 0;
  const votes = data.Votes || {};
  const reasons = data.HeuristicReasons || [];

  // Reset tabs to default active (Global APIs)
  tabBtnFeeds.click();

  // Verdict class
  const cls = verdict === 'PHISHING' ? 'phishing' : verdict === 'SUSPICIOUS' ? 'suspicious' : 'safe';
  resultCard.className = 'result-card ' + cls;

  // Icon
  const icons = { safe: '✅', suspicious: '⚠️', phishing: '🚨' };
  document.getElementById('verdictIcon').textContent = icons[cls];

  // Text
  document.getElementById('verdictText').textContent = verdict;
  document.getElementById('scoreText').textContent = score.toFixed(1) + ' / 10';

  // Score bar
  document.getElementById('scoreBar').style.width = (score * 10) + '%';

  // 1. Populate Global API Threat Feeds
  const feedsList = document.getElementById('feedsList');
  feedsList.innerHTML = '';
  
  const extFeeds = [
    { name: 'Google Safe Browsing', data: data.GoogleSafeBrowsing },
    { name: 'VirusTotal Reputation', data: data.VirusTotal },
    { name: 'IPQualityScore Threat Index', data: data.IPQualityScore }
  ];

  extFeeds.forEach(feed => {
    const status = (feed.data?.status || 'uncertain').toLowerCase();
    const msg = feed.data?.message || 'Threat scan unavailable';
    
    feedsList.innerHTML += `
      <div class="feed-item">
        <div class="feed-name-group">
          <span class="feed-name">${feed.name}</span>
          <span class="feed-message" title="${msg}">${msg}</span>
        </div>
        <span class="feed-badge ${status}">${status}</span>
      </div>
    `;
  });

  // Votes
  const votesGrid = document.getElementById('votesGrid');
  votesGrid.innerHTML = '';
  const voteLabels = [
    ['legit', 'Legit', votes.legit || 0],
    ['phishing', 'Phishing', votes.phishing || 0],
    ['suspicious', 'Suspicious', votes.suspicious || 0],
    ['uncertain', 'Uncertain', votes.uncertain || 0],
  ];
  voteLabels.forEach(([cls, label, count]) => {
    votesGrid.innerHTML += `
      <div class="vote-item">
        <div class="vote-dot ${cls}"></div>
        <span>${label}: <strong>${count}</strong></span>
      </div>`;
  });

  // 2. Populate Local Heuristics Details
  const heuristicDetailsGrid = document.getElementById('heuristicDetailsGrid');
  
  // Parse WHOIS Age
  const whoisData = data.WHOIS?.[1] || {};
  let ageVal = 'Unknown';
  let ageCls = '';
  if (whoisData.whois_success && whoisData.domain_age_days != null) {
    const days = whoisData.domain_age_days;
    ageVal = days + ' days';
    ageCls = days < 30 ? 'unsafe' : days < 90 ? 'warn' : 'safe';
  } else {
    ageCls = 'warn';
  }

  // Parse SSL status
  const sslStatus = data.SSL?.[1]?.ssl_status || 'Unknown';
  const sslCls = sslStatus === 'Valid' ? 'safe' : sslStatus === 'Invalid (HTTP)' ? 'unsafe' : 'warn';

  // Parse JS checks
  const jsData = data.JavaScript?.[1] || {};
  const jsVal = jsData.suspicious_scripts ? 'Obfuscated' : jsData.has_error ? 'Error' : 'Clean';
  const jsCls = jsData.suspicious_scripts ? 'unsafe' : jsData.has_error ? 'warn' : 'safe';

  // Parse HTML page status
  const htmlData = data.HTML?.[1] || {};
  let htmlVal = 'Clean';
  let htmlCls = 'safe';
  if (htmlData.has_error) {
    htmlVal = 'Error';
    htmlCls = 'warn';
  } else if (htmlData.has_password_field && htmlData.external_form_action) {
    htmlVal = 'Insecure Form';
    htmlCls = 'unsafe';
  } else if (htmlData.hidden_iframe) {
    htmlVal = 'Hidden Iframe';
    htmlCls = 'unsafe';
  } else if (htmlData.has_password_field) {
    htmlVal = 'Login Page';
    htmlCls = 'warn';
  }

  // Parse Free hosting
  const freeHosting = data.FreeHosting || {};
  const isFree = freeHosting.is_free_hosting;
  const hostingVal = isFree ? freeHosting.platform : 'Private Host';
  const hostingCls = freeHosting.contains_suspicious_keywords ? 'unsafe' : isFree ? 'warn' : 'safe';

  // Parse URL Entropy
  const lexicalData = data.Lexical?.[1] || {};
  const entropy = lexicalData.url_entropy || 0;
  const entropyVal = entropy.toFixed(2);
  const entropyCls = entropy > 4.5 ? 'unsafe' : entropy > 4.2 ? 'warn' : 'safe';

  heuristicDetailsGrid.innerHTML = `
    <div class="h-detail-item">
      <span class="h-detail-title">Domain Age</span>
      <span class="h-detail-value ${ageCls}">${ageVal}</span>
    </div>
    <div class="h-detail-item">
      <span class="h-detail-title">SSL Certificate</span>
      <span class="h-detail-value ${sslCls}">${sslStatus}</span>
    </div>
    <div class="h-detail-item">
      <span class="h-detail-title">JS Obfuscation</span>
      <span class="h-detail-value ${jsCls}">${jsVal}</span>
    </div>
    <div class="h-detail-item">
      <span class="h-detail-title">HTML Check</span>
      <span class="h-detail-value ${htmlCls}">${htmlVal}</span>
    </div>
    <div class="h-detail-item">
      <span class="h-detail-title">Hosting Platform</span>
      <span class="h-detail-value ${hostingCls}">${hostingVal}</span>
    </div>
    <div class="h-detail-item">
      <span class="h-detail-title">URL Entropy</span>
      <span class="h-detail-value ${entropyCls}">${entropyVal}</span>
    </div>
  `;

  // Reasons / Detection Signals
  const reasonsSection = document.getElementById('reasonsSection');
  const reasonsList = document.getElementById('reasonsList');
  if (reasons.length > 0) {
    reasonsList.innerHTML = reasons.map(r => `<div class="reason-item">${r}</div>`).join('');
    reasonsSection.classList.remove('hidden');
  } else {
    reasonsSection.classList.add('hidden');
  }

  resultCard.classList.remove('hidden');
}
