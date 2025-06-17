let privacyAlerts = [];

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "analyze_url") {
    fetch(`http://localhost:3000/analyze?domain=${encodeURIComponent(request.url)}`)
      .then(res => res.json())
      .then(data => sendResponse({ success: true, data, privacyAlerts }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  if (request.type === 'privacy_alert') {
    if (!privacyAlerts.includes(request.resource)) {
      privacyAlerts.push(request.resource);
    }
  }
});