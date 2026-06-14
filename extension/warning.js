const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || 'Unknown';
document.getElementById('target-url').textContent = targetUrl;

document.getElementById('go-back-btn').addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) {
      const tabId = tabs[0].id;
      chrome.tabs.goBack(tabId, () => {
        if (chrome.runtime.lastError) {
          // No back history or goBack is not possible, close the tab
          chrome.tabs.remove(tabId).catch(() => {
            window.location.href = 'https://www.google.com';
          });
        }
      });
    } else {
      window.location.href = 'https://www.google.com';
    }
  });
});

document.getElementById('proceed-btn').addEventListener('click', () => {
  if (targetUrl === 'Unknown') return;

  // Add URL to bypassed list in storage, then navigate
  chrome.storage.local.get(["bypassedUrls"], (result) => {
    const bypassed = result.bypassedUrls || [];
    if (!bypassed.includes(targetUrl)) {
      bypassed.push(targetUrl);
    }
    chrome.storage.local.set({ bypassedUrls: bypassed }, () => {
      window.location.href = targetUrl;
    });
  });
});
