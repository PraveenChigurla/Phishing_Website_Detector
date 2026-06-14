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

function renderResult(data) {
  const verdict = (data.Verdict || 'SAFE').toUpperCase();
  const score = data['Final Score'] || 0;
  const votes = data.Votes || {};
  const reasons = data.HeuristicReasons || [];

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

  // Reasons
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
