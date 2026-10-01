document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) return;

    try {
      const url = new URL(tabs[0].url);
      const domain = url.hostname.replace(/^www\./, "");
      document.getElementById("url").textContent = domain;

      // Read directly from session storage using the domain as key
      chrome.storage.session.get([domain], (result) => {
        if (result && result[domain]) {
          // Data already exists! Render immediately without calling background/fetch
          renderPopupUI(result[domain]);
        } else {
          // Fallback: Request background script if page script hasn't stored it yet
          chrome.runtime.sendMessage(
            { type: "analyze_url", url: domain, tabId: tabs[0].id },
            (response) => {
              if (response && response.success) {
                renderPopupUI(response.data);
              } else {
                document.getElementById("score").textContent = "Error loading data";
              }
            }
          );
        }
      });

      // Load Privacy Alerts for current tab
      chrome.runtime.sendMessage({ type: "get_privacy_alerts", tabId: tabs[0].id }, (response) => {
        const privacyList = document.getElementById("privacyAlerts");
        privacyList.innerHTML = "";
        if (response && response.alerts && response.alerts.length > 0) {
          response.alerts.forEach(alert => {
            const li = document.createElement("li");
            li.textContent = `${alert.charAt(0).toUpperCase() + alert.slice(1)} permission granted`;
            privacyList.appendChild(li);
          });
        } else {
          const li = document.createElement("li");
          li.textContent = "No active permission alerts";
          privacyList.appendChild(li);
        }
      });

    } catch (e) {
      document.getElementById("url").textContent = "Invalid Tab";
      document.getElementById("score").textContent = "N/A";
    }
  });
});

function renderPopupUI(data) {
  const score = data.trustScore;
  document.getElementById("score").textContent = score;

  const color = score > 80 ? "green" : score > 70 ? "greenyellow" : score > 60 ? "yellow" : score > 50 ? "orange" : "red";
  const result = score > 80 ? "Safe" : score > 70 ? "Not Fully Safe" : score > 60 ? "Moderately Safe" : score > 50 ? "Less Secure" : "Not Safe";

  const indicatorBg = document.getElementById("indicator-background");
  if (indicatorBg) indicatorBg.style.backgroundColor = color;
  
  const indicatorEl = document.getElementById("indicator");
  if (indicatorEl) indicatorEl.textContent = result;

  document.getElementById("phishing").textContent = data.phishing || "-";
  document.getElementById("scam").textContent = data.scam || "-";
  document.getElementById("spam").textContent = data.spam || "-";
  document.getElementById("malware").textContent = data.malware || "-";
  document.getElementById("safeBrowsing").textContent = data.safe_Browsing || "-";
}