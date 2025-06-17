document.addEventListener("DOMContentLoaded", () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = new URL(tabs[0].url);
    const domain = url.hostname.replace("www.", "");
    document.getElementById("url").textContent = domain;

    chrome.runtime.sendMessage({ type: "analyze_url", url: domain }, (response) => {
      if (response.success) {
        const data = response.data;
        const score = data.trustScore;
        document.getElementById("score").textContent = score;
        const color = score > 80 ? "green" : score > 70 ? "greenyellow" : score > 60 ? "yellow" : score > 50 ? "orange" : "red"
        const result = score > 80 ? "safe" : score > 70 ? "not Fully safe" : score > 60 ? "moderate safe" : score > 50 ? "not safe" : "not safe"
        document.getElementById("indicator-background").style.backgroundColor = color;
        document.getElementById("indicator").textContent = result;


        document.getElementById("phishing").textContent = data.phishing || "-";
        document.getElementById("scam").textContent = data.scam || "-";
        document.getElementById("spam").textContent = data.spam || "-";
        document.getElementById("malware").textContent = data.malware || "-";
        document.getElementById("safeBrowsing").textContent = data.safe_Browsing || "-";

        // Show privacy alerts
        const privacyList = document.getElementById("privacyAlerts");
        privacyList.innerHTML = "";
        (response.privacyAlerts || []).forEach(alert => {
          const li = document.createElement("li");
          li.textContent = `${alert.charAt(0).toUpperCase() + alert.slice(1)} permission used`;
          privacyList.appendChild(li);
        });
      } else {
        document.getElementById("score").textContent = "Error fetching data.";
      }
    });
  });

  document.getElementById("generatePwd").addEventListener("click", () => {
    const pwd = generatePassword(16);
    document.getElementById("password").textContent = pwd;
  });
});

function generatePassword(length = 16) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
  return [...Array(length)].map(() => chars.charAt(Math.floor(Math.random() * chars.length))).join('');
}