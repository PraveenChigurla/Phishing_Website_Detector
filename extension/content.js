// Inject stylesheet for the floating status badge
const style = document.createElement('style');
style.textContent = `
  .__phish_detector_badge {
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    z-index: 2147483647 !important; /* ensure it stays on top */
    background: rgba(15, 23, 42, 0.85) !important;
    backdrop-filter: blur(12px) !important;
    -webkit-backdrop-filter: blur(12px) !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
    border-radius: 16px !important;
    padding: 14px 16px !important;
    width: 280px !important;
    color: #f8fafc !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.4) !important;
    opacity: 0 !important;
    transform: translateY(20px) !important;
    transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.4s ease !important;
    pointer-events: auto !important;
    text-align: left !important;
  }
  .__phish_detector_badge.show {
    opacity: 1 !important;
    transform: translateY(0) !important;
  }
  .__phish_detector_header {
    display: flex !important;
    align-items: center !important;
    justify-content: space-between !important;
    margin-bottom: 6px !important;
  }
  .__phish_detector_title_group {
    display: flex !important;
    align-items: center !important;
    gap: 8px !important;
  }
  .__phish_detector_icon {
    font-size: 16px !important;
    line-height: 1 !important;
  }
  .__phish_detector_title {
    font-weight: 700 !important;
    font-size: 14px !important;
    letter-spacing: -0.2px !important;
    margin: 0 !important;
    padding: 0 !important;
  }
  .__phish_detector_close {
    background: none !important;
    border: none !important;
    color: #94a3b8 !important;
    font-size: 18px !important;
    cursor: pointer !important;
    padding: 0 !important;
    line-height: 1 !important;
    transition: color 0.2s !important;
  }
  .__phish_detector_close:hover {
    color: #f8fafc !important;
  }
  .__phish_detector_body {
    font-size: 12px !important;
    color: #cbd5e1 !important;
    line-height: 1.4 !important;
    margin: 0 !important;
    padding: 0 !important;
  }
  .__phish_detector_score_container {
    display: flex !important;
    align-items: center !important;
    gap: 8px !important;
    margin-top: 8px !important;
  }
  .__phish_detector_score_bar_bg {
    flex-grow: 1 !important;
    height: 6px !important;
    background: rgba(255, 255, 255, 0.1) !important;
    border-radius: 3px !important;
    overflow: hidden !important;
  }
  .__phish_detector_score_bar {
    height: 100% !important;
    border-radius: 3px !important;
    transition: width 0.6s cubic-bezier(0.16, 1, 0.3, 1) !important;
  }
  .__phish_detector_score_text {
    font-size: 11px !important;
    font-weight: 600 !important;
    color: #e2e8f0 !important;
    min-width: 50px !important;
    text-align: right !important;
  }
  /* Color themes */
  .__phish_detector_safe {
    border-left: 4px solid #10b981 !important;
  }
  .__phish_detector_safe .__phish_detector_title {
    color: #34d399 !important;
  }
  .__phish_detector_safe .__phish_detector_score_bar {
    background: #10b981 !important;
  }
  .__phish_detector_suspicious {
    border-left: 4px solid #fbbf24 !important;
  }
  .__phish_detector_suspicious .__phish_detector_title {
    color: #facc15 !important;
  }
  .__phish_detector_suspicious .__phish_detector_score_bar {
    background: #fbbf24 !important;
  }
  .__phish_detector_phishing {
    border-left: 4px solid #f87171 !important;
  }
  .__phish_detector_phishing .__phish_detector_title {
    color: #f87171 !important;
  }
  .__phish_detector_phishing .__phish_detector_score_bar {
    background: #f87171 !important;
  }
`;
document.head.appendChild(style);

let currentBadge = null;

// Function to render or update the badge
function showBadge(verdict, score) {
  // Remove existing badge if present
  if (currentBadge) {
    currentBadge.remove();
  }

  const badge = document.createElement('div');
  badge.className = '__phish_detector_badge';

  const isPhishing = verdict === 'PHISHING';
  const isSuspicious = verdict === 'SUSPICIOUS';

  let title = 'Safe Site';
  let icon = '🛡️';
  let themeClass = '__phish_detector_safe';
  let description = 'This website matches our safety guidelines.';

  if (isPhishing) {
    title = 'Phishing Alert';
    icon = '🚨';
    themeClass = '__phish_detector_phishing';
    description = 'High risk of credential theft or scan anomalies.';
  } else if (isSuspicious) {
    title = 'Suspicious';
    icon = '⚠️';
    themeClass = '__phish_detector_suspicious';
    description = 'Contains suspicious heuristic patterns.';
  }

  badge.classList.add(themeClass);

  badge.innerHTML = `
    <div class="__phish_detector_header">
      <div class="__phish_detector_title_group">
        <span class="__phish_detector_icon">${icon}</span>
        <span class="__phish_detector_title">${title}</span>
      </div>
      <button class="__phish_detector_close" title="Dismiss">&times;</button>
    </div>
    <div class="__phish_detector_body">
      ${description}
    </div>
    <div class="__phish_detector_score_container">
      <div class="__phish_detector_score_bar_bg">
        <div class="__phish_detector_score_bar" style="width: 0%"></div>
      </div>
      <span class="__phish_detector_score_text">${score.toFixed(1)} / 10</span>
    </div>
  `;

  document.body.appendChild(badge);
  currentBadge = badge;

  // Trigger animation after append
  setTimeout(() => {
    badge.classList.add('show');
    // Animate score bar
    const bar = badge.querySelector('.__phish_detector_score_bar');
    if (bar) {
      bar.style.width = `${score * 10}%`;
    }
  }, 100);

  // Close handler
  badge.querySelector('.__phish_detector_close').addEventListener('click', () => {
    badge.classList.remove('show');
    setTimeout(() => {
      badge.remove();
      if (currentBadge === badge) currentBadge = null;
    }, 400);
  });
}

// Request status from storage or listen to messages
function checkCurrentUrl() {
  const currentUrl = window.location.href;
  
  // Try retrieving cached data from chrome.storage.local
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get([currentUrl], (result) => {
      if (result && result[currentUrl]) {
        const scan = result[currentUrl];
        if (scan.verdict && scan.verdict !== 'PENDING') {
          showBadge(scan.verdict, scan.score);
        }
      }
    });
  }
}

// Listen to message updates from the background service worker
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'show_verdict') {
      const currentUrl = window.location.href;
      // Make sure the verdict is for this page URL
      if (request.url === currentUrl) {
        showBadge(request.verdict, request.score);
      }
    }
  });
}

// Run checks on page load
checkCurrentUrl();
