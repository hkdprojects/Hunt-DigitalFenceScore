// server.js
const express = require("express");
const path = require("path");
const cors = require("cors");
const getWhoisData = require("./api/whois");
const getReputationScore = require("./api/reputation");
const getSecurityDetails = require("./api/security");
const { calculateTrustScore } = require("./utils/scoreCalculator");
const { isAdult } = require("./utils/scoreCalculator");

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
    if (!domain) {
        return res.status(400).json({ error: "Domain is required!" });
    }

    try {
        const [whois, reputation, security] = await Promise.all([
            getWhoisData(domain),
            getReputationScore(domain),
            getSecurityDetails(domain),
        ]);

        //some intializations
        let safe_Browsing = isAdult(domain) ? "No" : "Yes";

        let registrantPhone = whois.WhoisRecord.registrant?.telephone ?? "N/A";
        let registrantEmail = whois.WhoisRecord.contactEmail || "N/A";
        let authorcredntials = registrantEmail ? 1 : registrantPhone ? 1 : 0;

        if (security.data.attributes.last_https_certificate &&
            security.data.attributes.last_https_certificate.subject
        ) {

            organization = security.data.attributes.last_https_certificate.subject.O;
        } else if (whois.WhoisRecord?.administrativeContact?.organization) {
            organization = whois.WhoisRecord?.administrativeContact?.organization ?? "N/A";
        } else if (whois.WhoisRecord.domainName) {
            organization = whois.WhoisRecord.domainName || "N/A"
        } else {
            organization = "N/A";
        }

        IP = whois.WhoisRecord.ips || "N/A";

        if (organization || IP) {
            domainId = 1;
        } else {
            domainId = 0;
        }




        // Extract needed values from responses
        const props = {
            httpscertificate: security?.data?.attributes?.last_https_certificate?.cert_signature?.signature || "N/A",
            sslcertificate: security?.data?.attributes?.last_https_certificate?.serial_number || "N/A",
            authorcredntials,
            domainId,
            webAge: calculateAge(whois?.WhoisRecord?.createdDateNormalized) || 0,
            reputation: reputation?.data?.attributes?.reputation || 0,
            alexaRank: security?.data?.attributes?.popularity_ranks?.Alexa?.rank || "N/A",
            phishing: security?.data?.attributes?.last_analysis_results?.Phishtank?.result === "clean" ? "Not Found" : "Found",
            scam: security?.data?.attributes?.last_analysis_results?.Scantitan?.result === "clean" ? "Not Found" : "Found",
            spam: security?.data?.attributes?.last_analysis_results?.Spam404?.result === "clean" ? "Not Found" : "Found",
            malware: security?.data?.attributes?.last_analysis_results?.Malwared?.result === "clean" ? "Not Found" : "Found",
            safe_Browsing,

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
            domain,
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
