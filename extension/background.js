chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Scanner extension installed.");
  });
  
  chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    const url = details.url;
  
    // Skip internal Chrome and extension URLs
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) return;
  
    try {
      const response = await fetch("http://127.0.0.1:8000/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });
  
      const data = await response.json();
      if (data["Verdict"] === "PHISHING") {
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}`)
        });
      }
    } catch (err) {
      console.error("Scan error:", err.message);
    }
  }, { url: [{ schemes: ["http", "https"] }] });
  