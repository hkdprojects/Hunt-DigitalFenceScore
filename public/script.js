// Data Constants
const under18Wbs = ["pornhub", "xnxx", "xhamster", "xmaster", "naughtyamerica", "altbalaji", "ullu", "aha"];

const unsafe = [
    "testphish.com", "examplephishing.com", "badsite.x10host.com",
    "suspicious-site.com", "spamdomain.com", "eicar.org",
    "safebrowsing/malware.html", "safebrowsing/phishing.html", "http.com"
];

const SHIELD_PATHS = {
    x: 'M6.146 5.146a.5.5 0 0 1 .708 0L8 6.293l1.146-1.147a.5.5 0 1 1 .708.708L8.707 7l1.147 1.146a.5.5 0 0 1-.708.708L8 7.707 6.854 8.854a.5.5 0 1 1-.708-.708L7.293 7 6.146 5.854a.5.5 0 0 1 0-.708',
    slash: 'M1.093 3.093c-.465 4.275.885 7.46 2.513 9.589a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7 7 0 0 0 1.048-.625 11.3 11.3 0 0 0 1.733-1.525l-.745-.745a10.3 10.3 0 0 1-1.578 1.392c-.346.244-.652.42-.893.533q-.18.085-.293.118a1 1 0 0 1-.101.025 1 1 0 0 1-.1-.025 2 2 0 0 1-.294-.118 6 6 0 0 1-.893-.533 10.7 10.7 0 0 1-2.287-2.233C3.053 10.228 1.879 7.594 2.06 4.06zM3.98 1.98l-.852-.852A59 59 0 0 1 5.072.559C6.157.266 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.483 3.626-.332 6.491-1.551 8.616l-.77-.77c1.042-1.915 1.72-4.469 1.29-7.702a.48.48 0 0 0-.33-.39c-.65-.213-1.75-.56-2.836-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524a50 50 0 0 0-1.357.39zm9.666 12.374-13-13 .708-.708 13 13z',
    exclamation: 'M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z',
    shield: '',
    check: 'M10.854 5.146a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7.5 7.793l2.646-2.647a.5.5 0 0 1 .708 0'
};

// DOM Elements
const domainInput_div = document.getElementById('search_content');
const loading_div = document.getElementById("loading");
const search_result_div = document.getElementById("search_result");
const background_div = document.getElementById("background");
const blank_div = document.getElementById("blank");

// Indicators & Scores
const webscore_div = document.getElementById("web-score");
const httpsBlock_div = document.getElementById("httpsBlock");
const sslc_div = document.getElementById("sslc");
const authorcredntials_div = document.getElementById("acd");
const domainId_div = document.getElementById("domainId");
const webAge_div = document.getElementById("age");

// Key details
const alexaRank_div = document.getElementById("alexaRank");
const website_type_div = document.getElementById("websiteType");
const DomainAge_div = document.getElementById("DomainAge");

// Organization details
const organization_div = document.getElementById("organization");
const organizationCountry_div = document.getElementById("organizationCountry");
const organizationCity_div = document.getElementById("organizationCity");
const organizationState_div = document.getElementById("organizationState");
const officialWebsite_div = document.getElementById("officialWebsite");

// Web Details
const websiteName_div = document.getElementById("websiteName");
const Reg_Web_div = document.getElementById("Reg-Web");
const IP_div = document.getElementById("IP");
const ssl_cert_div = document.getElementById("ssl-cert");
const domainExtension_div = document.getElementById("domainExtension");
const reputation_div = document.getElementById("reputation");
const validation_div = document.getElementById("validTill");

// Security
const malware_div = document.getElementById("malware");
const phishing_div = document.getElementById("phishing");
const scam_div = document.getElementById("scam");
const spam_div = document.getElementById("spam");
const safe_Browsing_div = document.getElementById("safeBrowsing");

// Registrant
const registrantName_div = document.getElementById("registrantName");
const registrantOrganization_div = document.getElementById("registrantOrganization");
const registrantCountry_div = document.getElementById("registrantCountry");
const registrantState_div = document.getElementById("registrantState");
const registrantCity_div = document.getElementById("registrantCity");
const registrantStreet_div = document.getElementById("registrantStreet");
const registrantPostalCode_div = document.getElementById("registrantPostalCode");
const registrantPhone_div = document.getElementById("registrantPhone");
const registrantEmail_div = document.getElementById("registrantEmail");

// Description
const description_container_div = document.getElementById("description-container");
const declaration_paragraph = document.getElementById("declaration");

// Dynamic Icons
const shieldIcon = document.getElementById("shield-icon");
const shieldInnerPath = document.getElementById("shield-inner-path");
const indicatorWrapper = document.getElementById("indicator");

// State Variables
let domain = "";
let webscore = 0;
let httpscertificate = "N/A";
let sslcertificate = "N/A";
let authorcredntials = 0;
let domainId = 0;
let webAge = 0;
let alexaRank = "N/A";
let website_type = "N/A";
let DomainAge = "N/A";
let organization = "N/A", organizationCountry = "N/A", organizationCity = "N/A", organizationState = "N/A", officialWebsite = "N/A";
let websiteName = "N/A", Reg_Web = "N/A", IP = "N/A", ssl_cert = "N/A", domainExtension = "N/A", reputation = 0, validTill = "N/A";
let malware = "Not Found", phishing = "Not Found", scam = "Not Found", spam = "Not Found", safe_Browsing = "Unknown";
let registrantName = "N/A", registrantOrganization = "N/A", registrantCountry = "N/A", registrantState = "N/A";
let registrantCity = "N/A", registrantStreet = "N/A", registrantPostalCode = "N/A", registrantPhone = "N/A", registrantEmail = "N/A";
let declaration = "";

// Event Listeners
document.getElementById("search_button").addEventListener("click", () => {
    domain = domainInput_div.value.trim();
    domainInputNull(domain);
});

document.getElementById("search_content").addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        event.preventDefault();
        domain = domainInput_div.value.trim();
        domainInputNull(domain);
    }
});

function domainInputNull(domainName) {
    if (!domainName) {
        hideResultDiv();
        hideErrorDiv();
        alert("Please enter a domain name");
    } else {
        getDetails(domainName);
    }
}

function evaluateDomain(domainName) {
    const lowerDomain = domainName.toLowerCase();
    const isKnownUnsafe = unsafe.some(item => lowerDomain.includes(item));

    if (isKnownUnsafe) {
        if (lowerDomain.includes("phish")) phishing = "Found";
        if (lowerDomain.includes("suspicious") || lowerDomain.includes("eicar") || lowerDomain.includes("malware")) malware = "Found";
        if (lowerDomain.includes("spam")) spam = "Found";
    }
}

function isAdult(domainName) {
    return under18Wbs.some(adult => domainName.toLowerCase().includes(adult));
}

function getAge(regDate) {
    if (!regDate) return 0;
    const currentDate = new Date();
    const reg = new Date(regDate);
    if (isNaN(reg.getTime())) return 0;

    let age = currentDate.getFullYear() - reg.getFullYear();
    if (currentDate.getMonth() < reg.getMonth() || (currentDate.getMonth() === reg.getMonth() && currentDate.getDate() < reg.getDate())) {
        age--;
    }
    return age < 0 ? 0 : age;
}

function verifyHttp() {
    const checks = {
        httpsBlock: httpscertificate !== "N/A",
        sslc: sslcertificate !== "N/A",
        authorCredentials: authorcredntials === 1,
        domainId: domainId === 1,
        webAge: webAge > 0
    };

    for (let key in checks) {
        if (checks[key]) webscore += 20;
    }

    if (webAge < 5) webscore -= 5;
    if (webAge <= 2) webscore -= 5;

    const numericReputation = Number(reputation);
    if (numericReputation < 600) {
        if (numericReputation === 0) {
            webscore -= 6;
        } else if (numericReputation < 1) {
            webscore -= 15;
        } else {
            let newreputation = Math.trunc(6 - (numericReputation / 100));
            if (newreputation < 1) newreputation = 1;
            webscore -= newreputation;
        }
    } else if (!reputation || reputation === "N/A") {
        webscore -= 5;
    }

    if (!alexaRank || alexaRank === "N/A" || alexaRank < 10) {
        webscore -= 2;
    }

    httpsBlock_div.innerHTML = checks.httpsBlock ? "Found" : "Not Found";
    sslc_div.innerHTML = checks.sslc ? "Found" : "Not Found";
    authorcredntials_div.innerHTML = checks.authorCredentials ? "Found" : "Not Found";
    domainId_div.innerHTML = checks.domainId ? "Found" : "Not Found";
    webAge_div.innerHTML = checks.webAge ? `${webAge} Years` : "Not Found";
}

function hideResultDiv() { search_result_div.style.display = "none"; }
function showResultDiv() { search_result_div.style.display = "flex"; }
function showErrorDiv() { blank_div.style.display = "block"; }
function hideErrorDiv() { blank_div.style.display = "none"; }
function showLoadingDiv() { loading_div.style.display = "flex"; background_div.style.display = "block"; }
function hideLoadingDiv() { loading_div.style.display = "none"; background_div.style.display = "none"; }

function clearOldData() {
    webscore_div.innerHTML = "00";
    
    // Clear DOM Text
    const targets = [
        httpsBlock_div, sslc_div, authorcredntials_div, domainId_div, webAge_div,
        reputation_div, DomainAge_div, website_type_div, alexaRank_div, organization_div,
        organizationCountry_div, organizationCity_div, organizationState_div, officialWebsite_div,
        websiteName_div, domainExtension_div, Reg_Web_div, IP_div, ssl_cert_div, description_container_div,
        declaration_paragraph, malware_div, phishing_div, scam_div, spam_div, safe_Browsing_div,
        registrantName_div, registrantOrganization_div, registrantCountry_div, registrantState_div,
        registrantCity_div, registrantStreet_div, registrantPostalCode_div, registrantPhone_div, registrantEmail_div
    ];
    targets.forEach(el => { if (el) el.innerHTML = ""; });

    // Reset variables
    spam = "Not Found";
    scam = "Not Found";
    phishing = "Not Found";
    malware = "Not Found";
}

function checkSafetyAndAlert() {

    if (phishing === "Found" || scam === "Found" || spam === "Found" || malware === "Found" || safe_Browsing === "No") {
        alert("This website is not safe to visit");

        if (phishing === "Found") { alert("This website is phishing"); webscore -= 15; }
        if (scam === "Found") { alert("This website is scam"); webscore -= 15; }
        if (spam === "Found") { alert("This website is spam"); webscore -= 15; }
        if (malware === "Found") { alert("This website is malware"); webscore -= 15; }
        if (safe_Browsing === "No") { alert("This website might contain adult content"); webscore -= 5; }
    }

    if (webscore < 0) webscore = 0;
    webscore_div.innerHTML = `${webscore}`;

    let color = "#32ff00";
    let pathData = SHIELD_PATHS.check;

    if (webscore < 50) {
        color = "#ff1d1d";
        pathData = SHIELD_PATHS.x;
        declaration = `Not Safe`;
        alert("This website is not safe to visit, low security score");
    } else if (webscore >= 50 && webscore < 65) {
        color = "#ffa500";
        pathData = SHIELD_PATHS.slash;
        declaration = `Less secure`;
        alert("This website is less safe to visit");
    } else if (webscore >= 65 && webscore < 75) {
        color = "#ffff00";
        pathData = SHIELD_PATHS.exclamation;
        declaration = `Moderate secure`;
        alert("This website might not be safe to visit (moderate safety)");
    } else if (webscore >= 75 && webscore < 80) {
        color = "#adff2f";
        pathData = SHIELD_PATHS.shield;
        declaration = `Not Fully Safe`;
        alert("This website is safe to visit but not fully");
    } else {
        color = "#32ff00";
        pathData = SHIELD_PATHS.check;
        declaration = `Safe`;
        alert("This website is safe to visit");
    }

    webscore_div.style.color = color;
    if (shieldIcon) shieldIcon.setAttribute("fill", color);
    if (indicatorWrapper) indicatorWrapper.style.borderColor = color;

    if (shieldInnerPath) {
        if (pathData) {
            shieldInnerPath.setAttribute("d", pathData);
            shieldInnerPath.style.display = "block";
        } else {
            shieldInnerPath.style.display = "none";
        }
    }
}

function createDisc() {
    const desc1 = `A website’s security and trustworthiness are critical for users when browsing or conducting online transactions. The webScore reflects overall safety based on SSL certificates, domain age, and threat analysis.`;
    const desc2 = `Registrant details (Name: ${registrantName}, Org: ${registrantOrganization}, Country: ${registrantCountry}) provide transparency about ownership.`;
    const desc3 = `Identifiers like Host: ${Reg_Web} and SSL Cert Status: ${ssl_cert} are essential indicators of safe, encrypted communications.`;
    const desc4 = `Organization details (${organization}, ${organizationCountry}) help verify platform legitimacy.`;
    const desc5 = `Security indicators: Malware: ${malware}, Phishing: ${phishing}, Scam: ${scam}, Spam: ${spam}, Safe Browsing: ${safe_Browsing}.`;
    const desc6 = `Reputation rating is ${reputation}, Domain Age is ${DomainAge} year(s), Category: ${website_type}, Alexa Rank: ${alexaRank}.`;
    const desc7 = `This website is ${declaration} to visit. Take proper security measures before proceeding.`;

    description_container_div.innerHTML = `
        <p>${desc1}</p>
        <p>${desc2}</p>
        <p>${desc3}</p>
        <p>${desc4}</p>
        <p>${desc5}</p>
        <p>${desc6}</p>
    `;
    declaration_paragraph.innerHTML = `<p>${desc7}</p>`;
}

function extractDomain(url) {
    try {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        const parsedUrl = new URL(url);
        return parsedUrl.hostname.replace(/^www\./, "");
    } catch (error) {
        console.error("Invalid URL:", url);
        return null;
    }
}

async function getDetails(rawDomain) {
    hideErrorDiv();
    hideResultDiv();
    showLoadingDiv();
    webscore = 0;
    clearOldData();
    await getResult(rawDomain);
    hideLoadingDiv();
}

async function getResult(rawDomain) {
    try {
        domain = extractDomain(rawDomain);
        if (!domain) throw new Error("Invalid domain format provided.");

        const response = await fetch(`/analyze?domain=${domain}`);
        if (!response.ok) {
            throw new Error(`Server returned status ${response.status} (${response.statusText})`);
        }

        const data = await response.json();

        if (!data || !data.whois?.WhoisRecord || !data.security || !data.reputation) {
            hideResultDiv();
            blank_div.innerHTML = `<p class="errordiv">No data received or invalid domain name</p>`;
            showErrorDiv();
            return;
        }

        if (data.whois.WhoisRecord.dataError === "MISSING_WHOIS_DATA" ||
            data.reputation.error || data.security.error) {
            hideResultDiv();
            blank_div.innerHTML = `<p class="errordiv">No information received or invalid domain name</p>`;
            showErrorDiv();
            return;
        }

        blank_div.style.display = "none";

        // HTTPS & SSL Certificates
        const certAttr = data.security?.data?.attributes?.last_https_certificate;
        httpscertificate = certAttr?.cert_signature?.signature || "N/A";
        sslcertificate = certAttr?.serial_number || "N/A";

        // Registrant Details
        const regObj = data.whois.WhoisRecord.registrant;
        registrantName = regObj?.name ?? "N/A";
        registrantOrganization = regObj?.organization ?? "N/A";
        registrantCountry = regObj?.country ?? "N/A";
        registrantState = regObj?.state ?? "N/A";
        registrantCity = regObj?.city ?? "N/A";
        registrantStreet = regObj?.street1 ?? "N/A";
        registrantPostalCode = regObj?.postalCode ?? "N/A";
        registrantPhone = regObj?.telephone ?? "N/A";
        registrantEmail = data.whois.WhoisRecord.contactEmail || "N/A";

        // Identity Flags
        authorcredntials = (registrantPhone !== "N/A" || registrantEmail !== "N/A") ? 1 : 0;
        
        // Key Facts
        alexaRank = data.security?.data?.attributes?.popularity_ranks?.Alexa?.rank || "N/A";
        website_type = data.security?.data?.attributes?.categories?.BitDefender || "N/A";
        DomainAge = getAge(data.whois.WhoisRecord.createdDateNormalized) || "N/A";
        webAge = typeof DomainAge === "number" ? DomainAge : 0;

        // Organization
        const repCertSub = data.reputation?.data?.attributes?.last_https_certificate?.subject;
        if (certAttr?.subject) {
            organization = certAttr.subject.O || "N/A";
            organizationCountry = certAttr.subject.C || "N/A";
            organizationState = repCertSub?.ST || "N/A";
            organizationCity = repCertSub?.L || "N/A";
        } else {
            organization = data.whois.WhoisRecord?.administrativeContact?.organization || data.whois.WhoisRecord.domainName || "N/A";
        }
        officialWebsite = data.whois.WhoisRecord.domainName || "N/A";

        // Web details
        websiteName = organization !== "N/A" ? organization : officialWebsite;
        domainExtension = data.whois.WhoisRecord.domainNameExt || "N/A";
        Reg_Web = data.whois.WhoisRecord.registrarName || "N/A";
        IP = data.whois.WhoisRecord.ips || "N/A";
        domainId = (websiteName !== "N/A" || IP !== "N/A") ? 1 : 0;

        ssl_cert = httpscertificate !== "N/A" ? "Found" : "Not Found";
        
        if (certAttr?.validity?.not_after) {
            validTill = getAge(certAttr.validity.not_after);
            validTill = validTill < 1 ? 1 : -1;
        } else {
            validTill = "N/A";
        }

        reputation = data.reputation?.data?.attributes?.reputation ?? 0;

        // Threat Scans
        const analysisResults = data.security?.data?.attributes?.last_analysis_results || {};
        malware = analysisResults.Malwared?.result === "clean" ? "Not Found" : "Found";
        phishing = analysisResults.Phishtank?.result === "clean" ? "Not Found" : "Found";
        scam = analysisResults.Scantitan?.result === "clean" ? "Not Found" : "Found";
        spam = analysisResults.Scantitan?.result === "clean" ? "Not Found" : "Found";

        if (analysisResults["Google Safe Browsing"]?.result) {
            safe_Browsing = (!isAdult(domain) && analysisResults["Google Safe Browsing"].result === "clean") ? "Yes" : "No";
        } else {
            safe_Browsing = "Unknown";
        }

        evaluateDomain(domain);

        // Render DOM Elements
        DomainAge_div.innerHTML = `${DomainAge}`;
        website_type_div.innerHTML = `${website_type}`;
        alexaRank_div.innerHTML = `${alexaRank}`;

        organization_div.innerHTML = `${organization}`;
        organizationCountry_div.innerHTML = `${organizationCountry}`;
        organizationCity_div.innerHTML = `${organizationCity}`;
        organizationState_div.innerHTML = `${organizationState}`;
        officialWebsite_div.innerHTML = `${officialWebsite}`;

        websiteName_div.innerHTML = `${websiteName}`;
        domainExtension_div.innerHTML = `${domainExtension}`;
        Reg_Web_div.innerHTML = `${Reg_Web}`;
        IP_div.innerHTML = `${IP}`;
        ssl_cert_div.innerHTML = `${ssl_cert}`;
        validation_div.innerHTML = `${validTill}`;
        reputation_div.innerHTML = `${reputation}`;

        malware_div.innerHTML = `${malware}`;
        phishing_div.innerHTML = `${phishing}`;
        scam_div.innerHTML = `${scam}`;
        spam_div.innerHTML = `${spam}`;
        safe_Browsing_div.innerHTML = `${safe_Browsing}`;

        registrantName_div.innerHTML = `${registrantName}`;
        registrantOrganization_div.innerHTML = `${registrantOrganization}`;
        registrantCountry_div.innerHTML = `${registrantCountry}`;
        registrantState_div.innerHTML = `${registrantState}`;
        registrantCity_div.innerHTML = `${registrantCity}`;
        registrantStreet_div.innerHTML = `${registrantStreet}`;
        registrantPostalCode_div.innerHTML = `${registrantPostalCode}`;
        registrantPhone_div.innerHTML = `${registrantPhone}`;
        registrantEmail_div.innerHTML = `${registrantEmail}`;

        verifyHttp();
        checkSafetyAndAlert();
        createDisc();
        showResultDiv();

    } catch (error) {
        console.error("Error fetching data:", error);
        blank_div.innerHTML = `<p class="errordiv">Error: ${error.message}</p>`;
        showErrorDiv();
    }
}

// Initial Initialization State
hideLoadingDiv();
hideResultDiv();
