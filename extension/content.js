(function () {
    const showSecureSurfAlert = (message, bgColor = "#f0f0f0") => {
        const alertBox = document.createElement("div");
        alertBox.innerHTML = message;

        Object.assign(alertBox.style, {
            position: "fixed",
            top: "20px",
            right: "20px",
            backgroundColor: bgColor,
            color: "#000",
            padding: "12px 16px",
            borderRadius: "8px",
            boxShadow: "0 4px 12px rgba(0, 0, 0, 0.2)",
            zIndex: "999999",
            fontSize: "14px",
            fontWeight: "bold",
            fontFamily: "Arial, sans-serif",
            width: "250px",
            minHeight: "100px",
        });

        document.body.appendChild(alertBox);
        setTimeout(() => alertBox.remove(), 5000);
    };

    const domain = location.hostname.replace(/^www\./, "");

    // Send request to background script to utilize caching
    chrome.runtime.sendMessage({ type: "analyze_url", url: domain }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
            console.error("SecureSurf fetch error:", response ? response.error : chrome.runtime.lastError);
            return;
        }

        const data = response.data;
        const score = data.trustScore;

        let message = `SecureSurf<br><br>
         ● URL: ${domain}<br>
         ● Score: ${score}<br>
         <br>
         ● Phishing: ${data.phishing || "-"}<br>
         ● Scam: ${data.scam || "-"}<br>
         ● Spam: ${data.spam || "-"}<br>
         ● Malware: ${data.malware || "-"}<br>
         ● Safe Browsing: ${data.safe_Browsing || "-"}`;

        let color = "#8bff6c";
        if (score <= 50) {
            color = "#f87883";
        } else if (score < 65) {
            color = "#ffa45f";
        } else if (score < 75) {
            color = "#fff35f";
        } else if (score < 80) {
            color = "#cfff5f";
        }

        showSecureSurfAlert(message, color);
    });

    // Privacy Guard - Camera/Mic/Location check
    ['camera', 'microphone', 'geolocation'].forEach(name => {
        navigator.permissions.query({ name }).then(result => {
            if (result.state === 'granted') {
                chrome.runtime.sendMessage({ type: 'privacy_alert', resource: name, granted: true });
            }
        });
    });
})();