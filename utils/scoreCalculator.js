// Adult content domain list
const under18Wbs = [
    "pornhub", "xnxx", "xhamster", "xmaster",
    "naughtyamerica", "altbalaji", "ullu", "aha"
];

// Known unsafe domain list
const nonSafe = [
    "testphish.com", "examplephishing.com", "badsite.x10host.com",
    "suspicious-site.com", "spamdomain.com", "example.com", "eicar.org",
    "safebrowsing/malware.html", "safebrowsing/phishing.html", "http.com"
];

function extractHostname(url) {
    if (!url) return '';
    try {
        const { hostname } = new URL(url.startsWith('http') ? url : `http://${url}`);
        return hostname.replace(/^www\./, '');
    } catch (e) {
        return url.replace(/^www\./, '').split('/')[0];
    }
}

function isAdult(domain) {
    const hostname = extractHostname(domain).toLowerCase();
    return under18Wbs.some(adult => hostname.includes(adult));
}

function checkNonSafeDomain(domain) {
    const hostname = extractHostname(domain).toLowerCase();

    const threatIndicators = {
        phishing: "Not Found",
        scam: "Not Found",
        spam: "Not Found",
        malware: "Not Found"
    };

    const matchedUnsafe = nonSafe.find(badDomain => hostname.includes(badDomain));
    if (matchedUnsafe) {
        if (matchedUnsafe.includes("phish")) threatIndicators.phishing = "Found";
        if (matchedUnsafe.includes("spam")) threatIndicators.spam = "Found";
        if (matchedUnsafe.includes("suspicious") || matchedUnsafe.includes("eicar") || matchedUnsafe.includes("malware")) {
            threatIndicators.malware = "Found";
        }
        if (matchedUnsafe.includes("scam") || matchedUnsafe.includes("badsite")) threatIndicators.scam = "Found";
    }

    return threatIndicators;
}

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

    // Core security checks
    if (httpscertificate && httpscertificate !== "N/A") webscore += 20;
    if (sslcertificate && sslcertificate !== "N/A") webscore += 20;
    if (authorcredntials && authorcredntials !== "N/A" && authorcredntials !== 0) webscore += 20;
    if (domainId && domainId !== "N/A" && domainId !== 0) webscore += 20;

    const parsedAge = Number(webAge);
    if (!isNaN(parsedAge) && parsedAge > 0) webscore += 20;

    // Age deduction logic
    if (!isNaN(parsedAge)) {
        if (parsedAge < 5) webscore -= 5;
        if (parsedAge <= 2) webscore -= 5;
    }

    // Reputation evaluation
    const numericReputation = Number(reputation);
    if (!isNaN(numericReputation)) {
        if (numericReputation < 600) {
            if (numericReputation === 0) {
                webscore -= 6;
            } else if (numericReputation < 1) {
                webscore -= 15;
            } else {
                let penalty = Math.trunc(6 - (numericReputation / 100));
                if (penalty < 1) penalty = 1;
                webscore -= penalty;
            }
        }
    } else {
        webscore -= 5;
    }

    // Popularity check
    const rank = Number(alexaRank);
    if (isNaN(rank) || rank < 10 || alexaRank === "N/A") {
        webscore -= 2;
    }

    // Threat penalties
    [phishing, scam, spam, malware].forEach(threat => {
        if (threat === "Found") webscore -= 15;
    });

    if (safe_Browsing === "No") webscore -= 5;

    // Bound output to valid percentage limits
    return Math.max(0, Math.min(webscore, 100));
}

module.exports = {
    isAdult,
    checkNonSafeDomain,
    calculateTrustScore
};