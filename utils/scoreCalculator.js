// List of adult content domains
const under18Wbs = [
    "pornhub", "xnxx", "xhamster", "xmaster",
    "naughtyamerica", "altbalaji", "ullu", "aha"
];

// List of known unsafe domains
const nonSafe = [
    "testphish.com", "examplephishing.com", "badsite.x10host.com",
    "suspicious-site.com", "spamdomain.com", "example.com","eicar.org",
    "safebrowsing/malware.html", "safebrowsing/phishing.html", "http.com"
];

// Extract hostname from URL or domain string
function extractHostname(url) {
    try {
        const { hostname } = new URL(url);
        return hostname.replace(/^www\./, '');
    } catch (e) {
        return url.replace(/^www\./, '');
    }
}

// Check if the domain is adult content
function isAdult(domain) {
    const hostname = extractHostname(domain);
    return under18Wbs.some(adult => hostname.includes(adult));
}

// Check for unsafe domains and return threat indicators
function checkNonSafeDomain(domain) {
    const hostname = extractHostname(domain);

    const threatIndicators = {
        phishing: "Not Found",
        scam: "Not Found",
        spam: "Not Found",
        malware: "Not Found"
    };

    if (nonSafe.some(badDomain => hostname.includes(badDomain))) {
        threatIndicators.phishing = "Found";
        threatIndicators.scam = "Found";
        threatIndicators.spam = "Found";
        threatIndicators.malware = "Found";
    }

    return threatIndicators;
}

// Calculate trust score based on multiple security factors
function calculateTrustScore({
    httpscertificate,
    sslcertificate,
    authorcredntials,
    domainId,
    webAge,
    reputation,
    alexaRank,
    phishing,
    scam,
    spam,
    malware,
    safe_Browsing
}) {
    let webscore = 0;

    // Basic security checks
    if (httpscertificate !== "N/A") webscore += 20;
    if (sslcertificate !== "N/A") webscore += 20;
    if (authorcredntials !== "N/A" && authorcredntials !== 0) webscore += 20;
    if (domainId !== "N/A" && domainId !== 0) webscore += 20;
    if (webAge !== "N/A" && typeof webAge === "number") webscore += 20;

    // Age penalties
    if (webAge < 5) webscore -= 5;
    if (webAge <= 2) webscore -= 5;

    // Reputation handling
    if (reputation < 600) {
        if (reputation === 0) {
            webscore -= 6;
        } else if (reputation < 1) {
            webscore -= 15;
        } else {
            let newreputation = reputation / 100;
            newreputation = 6 - newreputation;
            newreputation = Math.trunc(newreputation);
            if (!newreputation || newreputation === 0) {
                newreputation = 0;
            } else if (newreputation < 1) {
                newreputation = 1;
            }
            webscore -= newreputation;
        }
    } else if (!reputation || reputation === "N/A") {
        webscore -= 5;
    }

    // Alexa rank handling
    if (!alexaRank || alexaRank === "N/A" || alexaRank < 10) {
        webscore -= 2;
    }

    // Threat-based penalties
    const threats = [phishing, scam, spam, malware];
    threats.forEach(threat => {
        if (threat === "Found") webscore -= 15;
    });

    if (safe_Browsing === "No") webscore -= 5;

    // Final clamped score
    return Math.max(0, Math.min(webscore, 100));
}

module.exports = {
    isAdult,
    checkNonSafeDomain,
    calculateTrustScore
};
