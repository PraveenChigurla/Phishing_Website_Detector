const GLOBAL_WHITELIST = [
  "google.com", "youtube.com", "facebook.com", "wikipedia.org", "yahoo.com",
  "amazon.com", "twitter.com", "instagram.com", "linkedin.com", "reddit.com",
  "netflix.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
  "zoom.us", "live.com", "office.com", "bing.com", "pinterest.com",
  "fandom.com", "ebay.com", "imgur.com", "medium.com", "imdb.com",
  "dropbox.com", "salesforce.com", "craigslist.org", "adobe.com", "spotify.com"
];

function getDomain(url) {
  try {
    const parsed = new URL(url);
    let hostname = parsed.hostname;
    if (hostname.startsWith("www.")) {
      hostname = hostname.substring(4);
    }
    return hostname;
  } catch {
    return "";
  }
}

async function syncBackendPolicies() {
  try {
    const response = await fetch("http://127.0.0.1:8000/api/policy");
    if (response.ok) {
      const policies = await response.json();
      if (Array.isArray(policies)) {
        const whitelist = policies.filter(p => p.policy === 'whitelist').map(p => p.domain.toLowerCase());
        const blacklist = policies.filter(p => p.policy === 'blacklist').map(p => p.domain.toLowerCase());
        
        chrome.storage.local.set({ 
          syncedWhitelist: whitelist,
          syncedBlacklist: blacklist
        });
        console.log("Synced policies with Django backend:", { whitelist, blacklist });
      }
    }
  } catch (err) {
    console.warn("Could not sync policies with backend:", err.message);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing Scanner extension installed.");
  chrome.storage.local.clear();
  
  // Trigger initial policy sync
  syncBackendPolicies();
  
  // Setup alarm to sync policies every 30 minutes
  chrome.alarms.create("syncPoliciesAlarm", { periodInMinutes: 30 });
});

chrome.runtime.onStartup.addListener(() => {
  chrome.storage.local.remove("bypassedUrls");
  syncBackendPolicies();
  
  // Recreate the alarm on startup to ensure persistence
  chrome.alarms.create("syncPoliciesAlarm", { periodInMinutes: 30 });
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "syncPoliciesAlarm") {
    syncBackendPolicies();
  }
});

const recentScans = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only process main frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip internal Chrome and extension URLs
  if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;

  // Deduplicate rapid navigation triggers for the same URL in the same tab (within 3 seconds)
  const scanKey = `${details.tabId}-${url}`;
  const now = Date.now();
  if (recentScans.has(scanKey) && (now - recentScans.get(scanKey) < 3000)) {
    console.log("Deduplicated duplicate navigate trigger for:", url);
    return;
  }
  recentScans.set(scanKey, now);

  // Keep map size in check
  if (recentScans.size > 200) {
    for (const [key, time] of recentScans.entries()) {
      if (now - time > 10000) recentScans.delete(key);
    }
  }

  // Check bypass list, whitelist, and blacklist offline
  try {
    const storage = await chrome.storage.local.get(["bypassedUrls", "syncedWhitelist", "syncedBlacklist"]);
    const bypassed = storage.bypassedUrls || [];
    if (bypassed.includes(url)) {
      console.log("Bypassing scanning for user-permitted URL:", url);
      return;
    }

    const domain = getDomain(url).toLowerCase();
    if (domain) {
      // 1. Check Whitelist (Global & Synced)
      const syncedWhitelist = storage.syncedWhitelist || [];
      const isWhitelisted = GLOBAL_WHITELIST.includes(domain) || 
                            GLOBAL_WHITELIST.some(d => domain.endsWith("." + d)) ||
                            syncedWhitelist.includes(domain) ||
                            syncedWhitelist.some(d => domain.endsWith("." + d));

      if (isWhitelisted) {
        console.log("URL whitelisted locally (offline check):", url);
        const verdict = "SAFE";
        const score = 10.0;
        
        // Cache result
        const cacheObj = {};
        cacheObj[url] = { 
          verdict, 
          score, 
          data: { Verdict: verdict, "Final Score": score, HeuristicReasons: ["Locally Whitelisted"] }, 
          timestamp: Date.now() 
        };
        chrome.storage.local.set(cacheObj);

        // Broadcast to content script
        chrome.tabs.sendMessage(details.tabId, {
          action: "show_verdict",
          url,
          verdict,
          score
        }).catch(() => {});

        // Display check notification
        chrome.notifications.create(`scan-${details.tabId}`, {
          type: "basic",
          iconUrl: "icon.png",
          title: "🛡️ Site Checked: Safe (Trusted)",
          message: `${new URL(url).hostname} is on the local whitelist.`,
          priority: 2
        });

        // Silent background fetch to log this whitelisted visit in the SQLite database
        fetch("http://127.0.0.1:8000/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        }).catch(err => console.log("Silent whitelist log failed:", err.message));

        return;
      }

      // 2. Check Blacklist (Synced)
      const syncedBlacklist = storage.syncedBlacklist || [];
      const isBlacklisted = syncedBlacklist.includes(domain) ||
                            syncedBlacklist.some(d => domain.endsWith("." + d));

      if (isBlacklisted) {
        console.log("URL blacklisted locally (offline check):", url);
        const verdict = "PHISHING";
        const score = 0.0;

        // Cache result
        const cacheObj = {};
        cacheObj[url] = { 
          verdict, 
          score, 
          data: { Verdict: verdict, "Final Score": score, HeuristicReasons: ["Locally Blacklisted"] }, 
          timestamp: Date.now() 
        };
        chrome.storage.local.set(cacheObj);

        // Notify user
        chrome.notifications.create(`scan-${details.tabId}`, {
          type: "basic",
          iconUrl: "icon.png",
          title: "🚨 Security Alert: Phishing Blocked!",
          message: `${new URL(url).hostname} is locally blacklisted.`,
          priority: 2
        });

        // Silent background fetch to log this blacklisted hit in the SQLite database
        fetch("http://127.0.0.1:8000/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        }).catch(err => console.log("Silent blacklist log failed:", err.message));

        // Redirect immediately
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}`)
        });
        return;
      }
    }
  } catch (storageErr) {
    console.error("Storage error checking rules:", storageErr);
  }

  // Set status as PENDING
  const pendingObj = {};
  pendingObj[url] = { verdict: "PENDING", score: 0 };
  chrome.storage.local.set(pendingObj);

  try {
    const response = await fetch("http://127.0.0.1:8000/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url })
    });

    const data = await response.json();
    const verdict = data["Verdict"] || "SAFE";
    const score = data["Final Score"] != null ? data["Final Score"] : 10.0;

    // Cache the result
    const cacheObj = {};
    cacheObj[url] = { verdict, score, data, timestamp: Date.now() };
    chrome.storage.local.set(cacheObj);

    // Send result to the content script in this tab
    chrome.tabs.sendMessage(details.tabId, {
      action: "show_verdict",
      url,
      verdict,
      score
    }).catch(() => {
      // Content script might not be loaded yet, which is normal
    });

    // Create desktop notification
    let title = "🛡️ Site Checked: Safe";
    let message = `${new URL(url).hostname} is safe (Score: ${score.toFixed(1)}/10)`;
    
    if (verdict === "PHISHING") {
      title = "🚨 Security Alert: Phishing Blocked!";
      message = `${new URL(url).hostname} is flagged as PHISHING!`;
    } else if (verdict === "SUSPICIOUS") {
      title = "⚠️ Security Warning: Suspicious Site";
      message = `${new URL(url).hostname} is flagged as SUSPICIOUS (Score: ${score.toFixed(1)}/10).`;
    }

    // Overwrite previous notification for this tab instead of showing duplicates
    chrome.notifications.create(`scan-${details.tabId}`, {
      type: "basic",
      iconUrl: "icon.png",
      title: title,
      message: message,
      priority: 2
    });

    if (verdict === "PHISHING") {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}`)
      });
    }
  } catch (err) {
    console.error("Scan error:", err.message);
    chrome.storage.local.remove(url);
  }
}, { url: [{ schemes: ["http", "https"] }] });
  