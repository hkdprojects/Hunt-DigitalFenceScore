
const under18Wbs = ["pornhub", "xnxx", "xhamster", "xmaster", "naughtyamerica", "altbalaji", "ullu", "aha"];

function isAdult(domain) {

    if (under18Wbs.some(adult => domain.includes(adult))) {
        return true;
    } else {
        return false;
    }
}

function calculateTrustScore({ httpscertificate, sslcertificate, authorcredntials, domainId, webAge, reputation, alexaRank, phishing, scam, spam, malware, safe_Browsing }) {
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
    } else if (!reputation || reputation === "N/A" ) {
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

    return Math.max(0, Math.min(webscore, 100)); // Clamp between 0 and 100
}

module.exports = {isAdult,calculateTrustScore}
