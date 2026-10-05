(function () {
    // Avoid injecting duplicate toasts
    if (document.getElementById("securesurf-toast-host")) return;

    const showSecureSurfAlert = (domain, data, score) => {
        // Color mapping for Trust Score
        let badgeColor = "#10b981"; // Safe (Green)
        let statusText = "Safe Site";

        if (score <= 50) {
            badgeColor = "#ef4444"; // Dangerous (Red)
            statusText = "Unsafe Site";
        } else if (score < 65) {
            badgeColor = "#f97316"; // Warning (Orange)
            statusText = "High Risk";
        } else if (score < 75) {
            badgeColor = "#eab308"; // Caution (Yellow)
            statusText = "Moderate Risk";
        } else if (score < 80) {
            badgeColor = "#99ff00"; // Fair
            statusText = "Fairly Safe";
        }

        // Host Container & Shadow DOM to isolate styles from target webpage
        const host = document.createElement("div");
        host.id = "securesurf-toast-host";
        const shadow = host.attachShadow({ mode: "closed" });

        // Component Style Block
        const style = document.createElement("style");
        style.textContent = `
            .toast {
                position: fixed;
                top: 20px;
                right: 20px;
                width: 280px;
                background-color: #0f172a;
                color: #f8fafc;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                font-size: 13px;
                border-radius: 12px;
                box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3), 0 8px 10px -6px rgba(0, 0, 0, 0.2);
                z-index: 2147483647;
                padding: 14px;
                box-sizing: border-box;
                opacity: 0;
                transform: translateY(-10px);
                transition: opacity 0.3s ease, transform 0.3s ease;
            }
            .toast.show {
                opacity: 1;
                transform: translateY(0);
            }
            .header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 10px;
                padding-bottom: 8px;
                border-bottom: 1px solid #334155;
            }
            .brand {
                font-weight: 700;
                font-size: 14px;
                color: #38bdf8;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .close-btn {
                background: none;
                border: none;
                color: #94a3b8;
                font-size: 16px;
                cursor: pointer;
                padding: 0;
                line-height: 1;
            }
            .close-btn:hover { color: #ffffff; }
            .domain-info {
                font-size: 12px;
                color: #94a3b8;
                margin-bottom: 8px;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
            }
            .score-badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 6px;
                font-weight: 700;
                font-size: 12px;
                color: #ffffff;
                margin-bottom: 10px;
                background-color: ${badgeColor};
            }
            .threat-list {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 6px;
            }
            .threat-item {
                background: #1e293b;
                padding: 4px 6px;
                border-radius: 4px;
                font-size: 11px;
            }
            .threat-label { color: #94a3b8; }
            .threat-val { font-weight: 600; float: right; color: #f8fafc; }
        `;

        // Toast HTML Content Construction
        const toast = document.createElement("div");
        toast.className = "toast";

        toast.innerHTML = `
            <div class="header">
                <span class="brand">🛡️ SecureSurf</span>
                <button class="close-btn" id="close">&times;</button>
            </div>
            <div class="domain-info">Domain: <b>${escapeHTML(domain)}</b></div>
            <div>
                <span class="score-badge">Score: ${score} (${statusText})</span>
            </div>
            <div class="threat-list">
                <div class="threat-item"><span class="threat-label">Phishing</span><span class="threat-val">${escapeHTML(data.phishing || "-")}</span></div>
                <div class="threat-item"><span class="threat-label">Scam</span><span class="threat-val">${escapeHTML(data.scam || "-")}</span></div>
                <div class="threat-item"><span class="threat-label">Spam</span><span class="threat-val">${escapeHTML(data.spam || "-")}</span></div>
                <div class="threat-item"><span class="threat-label">Malware</span><span class="threat-val">${escapeHTML(data.malware || "-")}</span></div>
            </div>
        `;

        shadow.appendChild(style);
        shadow.appendChild(toast);
        document.body.appendChild(host);

        // Animation Entrance
        requestAnimationFrame(() => toast.classList.add("show"));

        // Close Action Handler
        const removeToast = () => {
            toast.classList.remove("show");
            setTimeout(() => host.remove(), 300);
        };

        toast.querySelector("#close").addEventListener("click", removeToast);
        setTimeout(removeToast, 6000); // Auto remove after 6s
    };

    // Helper function to prevent HTML/XSS injection
    const escapeHTML = (str) => {
        return String(str).replace(/[&<>"']/g, (m) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[m]);
    };

    const domain = location.hostname.replace(/^www\./, "");

    // Fetch site data via background service worker
    chrome.runtime.sendMessage({ type: "analyze_url", url: domain }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
            console.error("SecureSurf fetch error:", response ? response.error : chrome.runtime.lastError?.message);
            return;
        }

        const data = response.data;
        showSecureSurfAlert(domain, data, data.trustScore ?? 0);
    });

    // Privacy Guard Monitoring
    ['camera', 'microphone', 'geolocation'].forEach(name => {
        navigator.permissions.query({ name }).then(result => {
            if (result.state === 'granted') {
                chrome.runtime.sendMessage({ type: 'privacy_alert', resource: name, granted: true });
            }
        }).catch(() => {
            // Ignore browsers that don't support specific permission query targets
        });
    });
})();
