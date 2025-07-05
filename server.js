// server.js
const express = require("express");
const path = require("path");
const cors = require("cors");
const getWhoisData = require("./api/whois");
const getReputationScore = require("./api/reputation");
const getSecurityDetails = require("./api/security");
const { calculateTrustScore, checkNonSafeDomain, isAdult } = require("./utils/scoreCalculator");

require("dotenv").config();
const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(express.static("public"));
app.use(express.json());
app.use(cors());

// Serve index.html
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Analyze domain and return WHOIS, reputation, security, trustScore
app.get("/analyze", async (req, res) => {
    const domain = req.query.domain;
    if (!domain || domain === "localhost") {
        return res.status(400).json({ error: "Domain is required!" });
    }

    try {
        const [whois, reputation, security] = await Promise.all([
            getWhoisData(domain),
            getReputationScore(domain),
            getSecurityDetails(domain),
        ]);

        // Google Safe Browsing
        const googleSafe = security?.data?.attributes?.last_analysis_results?.["Google Safebrowsing"]?.result;

        // Safe browsing logic (prefer Google, fallback to isAdult)
        let safe_Browsing = "Unknown";
        if (googleSafe) {
            safe_Browsing = googleSafe === "clean" ? "Yes" : "No";
        } else if (isAdult(domain)) {
            safe_Browsing = "No";
        } else {
            safe_Browsing = "Yes";
        }

        const registrantPhone = whois.WhoisRecord.registrant?.telephone ?? "N/A";
        const registrantEmail = whois.WhoisRecord.contactEmail || "N/A";
        const authorcredntials = registrantEmail ? 1 : registrantPhone ? 1 : 0;

        let organization = "N/A";
        if (security.data.attributes.last_https_certificate?.subject?.O) {
            organization = security.data.attributes.last_https_certificate.subject.O;
        } else if (whois.WhoisRecord?.administrativeContact?.organization) {
            organization = whois.WhoisRecord.administrativeContact.organization;
        } else if (whois.WhoisRecord.domainName) {
            organization = whois.WhoisRecord.domainName;
        }

        const IP = whois.WhoisRecord.ips || "N/A";
        const domainId = (organization || IP) ? 1 : 0;

        // Get threat indicators from your own blocklist
        const {
            phishing: customPhishing,
            scam: customScam,
            spam: customSpam,
            malware: customMalware
        } = checkNonSafeDomain(domain);

        // Prepare input for scoring
        const props = {
            httpscertificate: security?.data?.attributes?.last_https_certificate?.cert_signature?.signature || "N/A",
            sslcertificate: security?.data?.attributes?.last_https_certificate?.serial_number || "N/A",
            authorcredntials,
            domainId,
            webAge: calculateAge(whois?.WhoisRecord?.createdDateNormalized) || 0,
            reputation: reputation?.data?.attributes?.reputation || 0,
            alexaRank: security?.data?.attributes?.popularity_ranks?.Alexa?.rank || "N/A",
            phishing: customPhishing,
            scam: customScam,
            spam: customSpam,
            malware: customMalware,
            safe_Browsing
        };

        const trustScore = calculateTrustScore(props);

        res.json({
            whois,
            reputation,
            security,
            trustScore,
            phishing: props.phishing,
            scam: props.scam,
            spam: props.spam,
            malware: props.malware,
            safe_Browsing,
            domain
        });
    } catch (error) {
        console.error("Error fetching data:", error);
        res.status(500).json({ error: "Failed to fetch data" });
    }
});

function calculateAge(createdDate) {
    if (!createdDate) return 0;
    const reg = new Date(createdDate);
    const now = new Date();
    let age = now.getFullYear() - reg.getFullYear();
    if (
        now.getMonth() < reg.getMonth() ||
        (now.getMonth() === reg.getMonth() && now.getDate() < reg.getDate())
    ) {
        age--;
    }
    return age;
}

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
