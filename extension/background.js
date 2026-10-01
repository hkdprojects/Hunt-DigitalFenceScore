const privacyAlertsByTab = {};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : request.tabId;

  // Track privacy alerts
  if (request.type === 'privacy_alert') {
    if (tabId) {
      if (!privacyAlertsByTab[tabId]) privacyAlertsByTab[tabId] = [];
      if (!privacyAlertsByTab[tabId].includes(request.resource)) {
        privacyAlertsByTab[tabId].push(request.resource);
      }
    }
    return;
  }

  // Retrieve privacy alerts
  if (request.type === 'get_privacy_alerts') {
    sendResponse({ alerts: privacyAlertsByTab[request.tabId] || [] });
    return;
  }

  // Handle URL analysis with mandatory caching
  if (request.type === "analyze_url") {
    const domain = request.url;

    chrome.storage.session.get([domain], (result) => {
      // Return cached copy if available
      if (result && result[domain]) {
        sendResponse({ success: true, data: result[domain], cached: true });
      } else {
        // Only fetch if not present in storage
        fetch(`http://localhost:3000/analyze?domain=${encodeURIComponent(domain)}`)
          .then(res => {
            if (!res.ok) throw new Error(`HTTP error! Status: ${res.status}`);
            return res.json();
          })
          .then(data => {
            // Save to chrome.storage.session so popup.js & content.js can access it instantly
            chrome.storage.session.set({ [domain]: data }, () => {
              sendResponse({ success: true, data, cached: false });
            });
          })
          .catch(err => sendResponse({ success: false, error: err.message }));
      }
    });

    return true; // Asynchronous response flag
  }
});

// Clean up tab privacy tracking when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete privacyAlertsByTab[tabId];
});
