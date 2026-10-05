document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0] || !tabs[0].url) return;

    try {
      const url = new URL(tabs[0].url);
      const domain = url.hostname.replace(/^www\./, "");
      document.getElementById("url").textContent = domain;

      // Check storage for pre-fetched analysis
      chrome.storage.session.get([domain], (result) => {
        if (result && result[domain]) {
          renderPopupUI(result[domain]);
        } else {
          chrome.runtime.sendMessage(
            { type: "analyze_url", url: domain, tabId: tabs[0].id },
            (response) => {
              if (response && response.success) {
                renderPopupUI(response.data);
              } else {
                document.getElementById("score").textContent = "N/A";
              }
            }
          );
        }
      });

      // Load Privacy Guard Alerts
      chrome.runtime.sendMessage({ type: "get_privacy_alerts", tabId: tabs[0].id }, (response) => {
        const privacyList = document.getElementById("privacyAlerts");
        privacyList.innerHTML = "";
        if (response && response.alerts && response.alerts.length > 0) {
          response.alerts.forEach(alert => {
            const li = document.createElement("li");
            li.textContent = `${alert.charAt(0).toUpperCase() + alert.slice(1)} permission requested`;
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
      document.getElementById("score").textContent = "--";
    }
  });
});

function renderPopupUI(data) {
  const score = data.trustScore ?? 0;
  const scoreEl = document.getElementById("score");
  scoreEl.textContent = score;

  // Determine Trust Color Palette
  let color = "#10b981"; // Safe (Green)
  let resultText = "Safe";

  if (score <= 50) {
    color = "#ef4444"; // Danger (Red)
    resultText = "Not Safe";
  } else if (score < 65) {
    color = "#f97316"; // Warning (Orange)
    resultText = "Less Secure";
  } else if (score < 75) {
    color = "#eab308"; // Caution (Yellow)
    resultText = "Moderate";
  } else if (score < 80) {
    color = "#84cc16"; // Light Green
    resultText = "Fairly Safe";
  }

  scoreEl.style.color = color;

  const indicatorBg = document.getElementById("indicator-background");
  if (indicatorBg) {
    indicatorBg.style.backgroundColor = color;
  }

  const indicatorEl = document.getElementById("indicator");
  if (indicatorEl) {
    indicatorEl.textContent = resultText;
  }

  // Helper to format threat status pills
  const updateThreatPill = (elementId, value) => {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    const formattedVal = value || "Clean";
    el.textContent = formattedVal;
    
    if (formattedVal.toLowerCase() === "found") {
      el.className = "pill found";
    } else {
      el.className = "pill clean";
    }
  };

  updateThreatPill("phishing", data.phishing);
  updateThreatPill("scam", data.scam);
  updateThreatPill("spam", data.spam);
  updateThreatPill("malware", data.malware);
  updateThreatPill("safeBrowsing", data.safe_Browsing === "No" ? "Found" : "Clean");
}