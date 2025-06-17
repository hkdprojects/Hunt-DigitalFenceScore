//search variable
//adultWebsites
let under18Wbs = ["pornhub", "xnxx", "xhamster", "xmaster", "naughtyamerica", "altbalaji", "ullu", "aha"];

let domainInput_div = document.getElementById('search_content');
let domain;

//animation div variable
const loading_div = document.getElementById("loading");
const search_result_div = document.getElementById("search_result");
const background_div = document.getElementById("background");

//result variables
let webscore_div = document.getElementById("web-score");
let webscore = 0;
const httpsBlock_div = document.getElementById("httpsBlock");
let httpsBlock;
const sslc_div = document.getElementById("sslc");
let sslc;
const authorcredntials_div = document.getElementById("acd");
let authorcredntials = 0;
const domainId_div = document.getElementById("domainId");
let domainId = 0;
const webAge_div = document.getElementById("age");
let webAge = 0;

//key details
const alexaRank_div = document.getElementById("alexaRank");
let alexaRank;
const website_type_div = document.getElementById("websiteType");
let website_type;
const DomainAge_div = document.getElementById("DomainAge");
let DomainAge;

//details variables

const organization_div = document.getElementById("organization");
let organization;
const organizationCountry_div = document.getElementById("organizationCountry");
let organizationCountry;
const organizationCity_div = document.getElementById("organizationCity");
let organizationCity;
const organizationState_div = document.getElementById("organizationState");
let organizationState;
const officialWebsite_div = document.getElementById("officialWebsite");
let officialWebsite;

//who is
let httpscertificate;
let sslcertificate;
const websiteName_div = document.getElementById("websiteName");
let websiteName;
const Reg_Web_div = document.getElementById("Reg-Web");
let Reg_Web;
const IP_div = document.getElementById("IP");
let IP;
const ssl_cert_div = document.getElementById("ssl-cert");
let ssl_cert;
const domainExtension_div = document.getElementById("domainExtension");
let domainExtension;
const reputation_div = document.getElementById("reputation");
let reputation;
const validation_div = document.getElementById("validTill");
let validTill = 0;


//security variables
const malware_div = document.getElementById("malware");
let malware;
const phishing_div = document.getElementById("phishing");
let phishing;
const scam_div = document.getElementById("scam");
let scam;
const spam_div = document.getElementById("spam");
let spam;
const safe_Browsing_div = document.getElementById("safeBrowsing");
let safe_Browsing;

//registrant variables
const registrantName_div = document.getElementById("registrantName");
let registrantName;
const registrantOrganization_div = document.getElementById("registrantOrganization");
let registrantOrganization;
const registrantCountry_div = document.getElementById("registrantCountry");
let registrantCountry;
const registrantState_div = document.getElementById("registrantState");
let registrantState;
const registrantCity_div = document.getElementById("registrantCity");
let registrantCity;
const registrantStreet_div = document.getElementById("registrantStreet");
let registrantStreet;
const registrantPostalCode_div = document.getElementById("registrantPostalCode");
let registrantPostalCode;
const registrantPhone_div = document.getElementById("registrantPhone");
let registrantPhone;
const registrantEmail_div = document.getElementById("registrantEmail");
let registrantEmail;

//description variable
const description_container_div = document.getElementById("description-container");
const declaration_paragraph = document.getElementById("declaration");
let description1;
let description2;
let description3;
let description4;
let description5;
let description6;
let declaration;
let description7;

//blank variable
let blank_div = document.getElementById("blank");

//expression div
let indicator_div = document.getElementById('indicator');
let expression_div = document.getElementById('expression');

//null check
function domainInputNull(domain) {
    if (domain === "") {
        expression_div.classList.remove(...expression_div.classList);
        normalExpression();
        hideResultDiv();
        hideErrorDiv();
        alert("Please enter a domain name");
    } else {
        getDetails(domain);

    }
}

//button and enter function
document.getElementById("search_button").addEventListener("click", function () {
    domain = domainInput_div.value.trim();
    domainInputNull(domain);
    console.log("Search button clicked, domain:", domain); // Log the domain
});

document.getElementById("search_content").addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        event.preventDefault();
        domain = domainInput_div.value.trim();
        domainInputNull(domain)
        console.log("Enter key pressed, domain:", domain); // Log the domain
    }
});


// under 18 safe check
function isAdult(domain) {
    if (under18Wbs.some(adult => domain.includes(adult))) {
        return true;
    } else {
        return false;
    }
}


function getAge(regDate) {
    let currentDate = new Date();
    let reg = new Date(regDate);
    let newage = currentDate.getFullYear() - reg.getFullYear();
    if (currentDate.getMonth() < reg.getMonth() || (currentDate.getMonth() === reg.getMonth() && currentDate.getDate() < reg.getDate())) {
        newage--;
    }
    if (!newage) {
        return 0;
    } else {
        return newage;
    }
}


//web score function
function verifyHttp(domain) {
    const checks = {
        httpsBlock: httpscertificate !== "N/A",
        sslc: sslcertificate !== "N/A",
        authorCredentials: authorcredntials !== "N/A",
        domainId: domainId !== "N/A",
        webAge: webAge !== "N/A"
    };

    for (let key in checks) {
        if (checks[key]) {
            webscore += 20;
        }
    }

    //based on age
    if (webAge < 5) {
        webscore -= 5;
    }
    if (webAge <= 2) {
        webscore -= 5;
    }

    //based on reputation score
    if (reputation < 600) {
        if (reputation === 0) {
            webscore -= 6;

        } else if (reputation < 1) {
            webscore -= 15;
        } else {
            let newreputation = reputation / 100;
            newreputation = 6 - newreputation;
            newreputation = Math.trunc(newreputation)
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

    //based on alexa score
    if (!alexaRank || alexaRank === "N/A" || alexaRank < 10) {
        webscore -= 2;
    }

    //update
    httpsBlock_div.innerHTML = checks.httpsBlock ? "Found" : "Not Found";
    sslc_div.innerHTML = checks.sslc ? "Found" : "Not Found";
    authorcredntials_div.innerHTML = checks.authorCredentials ? "Found" : "Not Found";
    domainId_div.innerHTML = checks.domainId ? "Found" : "Not Found";
    webAge_div.innerHTML = checks.webAge ? `${webAge}` : "Not Found";
}

function hideResultDiv() {
    search_result_div.style.display = "none";
}

function showResultDiv() {
    search_result_div.style.display = "flex";

}

function showErrorDiv() {
    blank_div.style.display = "block";

}

function hideErrorDiv() {
    blank_div.style.display = "none";

}

function clearOldData() {
    //clear score
    webscore_div.innerHTML = "00";

    //clear result option
    httpsBlock_div.innerHTML = "Not Found";
    sslc_div.innerHTML = "Not Found";
    authorcredntials_div.innerHTML = "Not Found";
    domainId_div.innerHTML = "Not Found";
    webAge_div.innerHTML = "Not Found";

    // Clear summary data
    reputation_div.innerHTML = "";
    DomainAge_div.innerHTML = "";
    website_type_div.innerHTML = "";
    alexaRank_div.innerHTML = "";

    // Clear details data
    organization_div.innerHTML = "";
    organizationCountry_div.innerHTML = "";
    organizationCity_div.innerHTML = "";
    organizationState_div.innerHTML = "";
    officialWebsite_div.innerHTML = "";

    // Clear web details data
    websiteName_div.innerHTML = "";
    domainExtension_div.innerHTML = "";
    Reg_Web_div.innerHTML = "";
    IP_div.innerHTML = "";
    ssl_cert_div.innerHTML = "";

    // Clear decription
    description_container_div.innerHTML = "";
    declaration_paragraph.innerHTML = ""

    // Clear security data
    malware_div.innerHTML = "";
    phishing_div.innerHTML = "";
    scam_div.innerHTML = "";
    spam_div.innerHTML = "";
    safe_Browsing_div.innerHTML = "";

    // Clear registrant data
    registrantName_div.innerHTML = "";
    registrantOrganization_div.innerHTML = "";
    registrantCountry_div.innerHTML = "";
    registrantState_div.innerHTML = "";
    registrantCity_div.innerHTML = "";
    registrantStreet_div.innerHTML = "";
    registrantPostalCode_div.innerHTML = "";
    registrantPhone_div.innerHTML = "";
    registrantEmail_div.innerHTML = "";
}

function showLoadingDiv() {
    loading_div.style.display = "flex";
    background_div.style.display = "block"

}

function hideLoadingDiv() {
    loading_div.style.display = "none";
    background_div.style.display = "none"

}

function normalExpression() {
    expression_div.classList.add("expression-normal");
    indicator_div.style.backgroundColor = "";
    webscore_div.style.backgroundColor = "";
}


function checkSafetyAndAlert() {
    // remove class for expression
    expression_div.classList.remove(...expression_div.classList);

    if (phishing === "Found" || scam === "Found" || spam === "Found" || malware === "Found" || safe_Browsing === "No") {
        alert("This website is not safe to visit");

        if (phishing === "Found") {
            alert("This website is phishing");
            webscore -= 15;
        }
        if (scam === "Found") {
            alert("This website is scam");
            webscore -= 15;
        }
        if (spam === "Found") {
            alert("This website is spam");
            webscore -= 15;
        }
        if (malware === "Found") {
            alert("This website is malware");
            webscore -= 15;
        }
        if (safe_Browsing === "No") {
            alert("This website might adultary content");
            webscore -= 5;
        }
    }
    webscore_div.innerHTML = `${webscore}`;

    console.log(webAge);
    console.log(domainId);
    
    if (webscore < 50) {
        expression_div.classList.add("expression-Bad");
        indicator_div.style.backgroundColor = "#ff1d1d";  //red
        webscore_div.style.backgroundColor = "#ff1d1d";
        declaration = `Not Safe`;

        alert("This website is not safe to visit,low security score")
    }

    if (webscore >= 50 && webscore < 65) {
        expression_div.classList.add("expression-notBad");
        indicator_div.style.backgroundColor = "#ffa500";  //orange
        webscore_div.style.backgroundColor = "#ffa500";
        declaration = `Less secure`;

        alert("This website is less safe to visit ")


    } else if (webscore >= 65 && webscore < 75) {
        expression_div.classList.add("expression-ok");
        indicator_div.style.backgroundColor = "#bbbb18";  //yellow
        webscore_div.style.backgroundColor = "#ffff00";
        declaration = `Moderate secure`;

        alert("This website is might not safe to visit (moderate safety)")


    } else if (webscore >= 75 && webscore < 80) {
        expression_div.classList.add("expression-Good");
        indicator_div.style.backgroundColor = "#adff2f";  //greenyellow
        webscore_div.style.backgroundColor = "#b4ff00";
        declaration = `Not Fully Safe`;

        alert("This website is safe to visit but Not fully")


    } else if (webscore >= 80) {
        expression_div.classList.add("expression-VeryGood");
        indicator_div.style.backgroundColor = "#01b501";  //green
        webscore_div.style.backgroundColor = "#32ff00";
        declaration = `Safe`;

        alert("This website is safe to visit")


    }
}
function createDisc() {
    description1 = `A website’s security and trustworthiness are critical for users when browsing or conducting online transactions. The webScore reflects the overall safety and reliability of a website based on various factors like SSL certificates, domain age, and security analysis. A high webScore indicates that the website follows industry-standard security measures.`
    description2 = `The registrant details, including registrantName, registrantOrganization, registrantCountry, registrantState, registrantCity, registrantStreet, registrantPostalCode, registrantPhone, and registrantEmail, provide transparency about the entity owning the website. Verifying these details helps users ensure they are dealing with legitimate businesses or individuals.`
    description3 = `Website identifiers such as websiteName, domainExtension, Reg_Web (registered web host), and ssl_cert (SSL certificate) are essential indicators of a secure platform. SSL certificates ensure encrypted communication, safeguarding users' sensitive data during transactions.`
    description4 = `Information about the organization behind the website, including organizationName, organizationCountry, organizationCity, organizationState, and officialWebsite, adds another layer of trust. Users can verify this information to confirm the credibility of the platform.`
    description5 = `Security indicators like malware is ${malware}, phishing is ${phishing}, scam is ${scam}, spam is ${spam}, and safe_Browsing provide insights into potential threats. A secure website will be free of malware, phishing attempts, scams, and spam, while also being recognized as safe by services like Google Safe Browsing.`
    description6 = `Finally, reputation of the website is ${reputation}, DomainAge of the ${DomainAge}, website type is ${website_type}, and alexaRank is ${alexaRank} are important metrics. A good reputation, an older domain, a clear website type, and a favorable Alexa ranking signal that the website is well-established, reliable, and trusted by other users globally. For users, checking these elements before engaging with a website ensures safe browsing and secure transactions.`
    description7 = `This website is ${declaration} to visit, \n Take security measure before use or visit(we mensioned some security mesures below), \n Do any thing at your own risk`
    description_container_div.innerHTML = `<p>${description1}</p>
        <p>${description2}</p>
        <p>${description3}</p>
        <p>${description4}</p>
        <p>${description5}</p>
        <p>${description6}</p>`;

    declaration_paragraph.innerHTML = `<p>${description7}</p>`
}


//frontend appierence
async function getDetails(domain) {
    hideErrorDiv();
    hideResultDiv();
    showLoadingDiv();
    webscore = 0; // Reset webscore
    clearOldData(); // Clear old data
    await getResult(domain);
    hideLoadingDiv();
}


//filter
function extractDomain(url) {
    try {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }

        const parsedUrl = new URL(url);
        let hostname = parsedUrl.hostname;

        if (hostname.startsWith("www.")) {
            hostname = hostname.replace("www.", "");
        }

        return hostname;
    } catch (error) {
        console.error("Invalid URL:", url);
        return null;
    }
}


//search function
async function getResult(domain) {
    try {
        domain = extractDomain(domain)
        console.log("Fetching data for domain:", domain); // Log the domain before fetch
        const response = await fetch(`/analyze?domain=${domain}`);
        const data = await response.json();

        console.log("Received data:", data); // Log the received data

        if (!data || !data.whois.WhoisRecord || !data.security || !data.reputation) {
            hideResultDiv();
            normalExpression();
            blank_div.innerHTML = `<p class="errordiv">No data received or invalid domain name</p>`;
            showErrorDiv();

        } else if (data.whois.WhoisRecord.dataError === "MISSING_WHOIS_DATA" ||
            data.reputation.error === "Failed to fetch reputation score" || data.security.error === "Failed to fetch reputation score") {
            hideResultDiv();
            normalExpression();
            blank_div.innerHTML = `<p class="errordiv">No information received or invalid domain name</p>`;
            showErrorDiv();

        } else {
            blank_div.style.display = "none";

            //summary update
            //https certificate
            if (data.security.data.attributes.last_https_certificate &&
                data.security.data.attributes.last_https_certificate.cert_signature.signature
            ) {
                httpscertificate = data.security.data.attributes.last_https_certificate.cert_signature.signature;

            } else {
                httpscertificate = "N/A"
            }

            //ssl certificate
            if (data.security.data.attributes.last_https_certificate &&
                data.security.data.attributes.last_https_certificate.serial_number
            ) {
                sslcertificate = data.security.data.attributes.last_https_certificate.serial_number;

            } else {
                sslcertificate = "N/A"
            }

            //registrant details
            if (registrantPhone || registrantEmail) {
                authorcredntials = 1;
            } else {
                authorcredntials = 0;
            }
            if (websiteName || IP) {
                domainId = 1;
            } else {
                domainId = 0;
            }
            webAge = getAge(data.whois.WhoisRecord.createdDateNormalized);

            // keyfacts
            if (data.security.data.attributes.popularity_ranks.Alexa) {
                alexaRank = data.security.data.attributes.popularity_ranks.Alexa.rank;
            } else {
                alexaRank = "N/A";
            }
            website_type = data.security.data.attributes.categories.BitDefender || "N/A";
            DomainAge = getAge(data.whois.WhoisRecord.createdDateNormalized) || "N/A";

            // Details
            if (data.security.data.attributes.last_https_certificate &&
                data.security.data.attributes.last_https_certificate.subject
            ) {

                organization = data.security.data.attributes.last_https_certificate.subject.O;
                organizationCountry = data.security.data.attributes.last_https_certificate.subject.C;
                organizationState = data.reputation.data.attributes.last_https_certificate.subject.ST;
                organizationCity = data.reputation.data.attributes.last_https_certificate.subject.L;

            } else if (data.whois.WhoisRecord?.administrativeContact?.organization) {
                organization = data.whois.WhoisRecord?.administrativeContact?.organization ?? "N/A";
            } else if (data.whois.WhoisRecord.domainName) {
                organization = whois.WhoisRecord.domainName || "N/A"
            } else {
                organization = "N/A";
                organizationCountry = "N/A";
                organizationState = "N/A";
                organizationCity = "N/A";
            }
            officialWebsite = data.whois.WhoisRecord.domainName || "N/A";


            // Web details
            websiteName = organization;
            domainExtension = data.whois.WhoisRecord.domainNameExt || "N/A";
            Reg_Web = data.whois.WhoisRecord.registrarName || "N/A";
            IP = data.whois.WhoisRecord.ips || "N/A";
            ssl_cert = httpscertificate;
            if (data.security.data.attributes.last_https_certificate &&
                data.security.data.attributes.last_https_certificate.validity
            ) {
                validTill = getAge(data.security.data.attributes.last_https_certificate.validity.not_after)

            } else {
                validTill = "N/A"
            }
            if (validTill && validTill < 1) {
                validTill = 1;
            } else {
                validTill = -1;
            }
            reputation = data.reputation.data.attributes.reputation || "0";

            // Security details
            //malware
            if (data.security.data.attributes.last_analysis_results.Malwared.result === "clean") {
                malware = "Not Found";
            } else {
                malware = "Found";
            }

            //phishing
            if (data.security.data.attributes.last_analysis_results.Phishtank.result === "clean") {
                phishing = "Not Found";
            } else {
                phishing = "Found";
            }

            //scam
            if (data.security.data.attributes.last_analysis_results.Scantitan.result === "clean") {
                scam = "Not Found";
            } else {
                scam = "Found";
            }

            //spam
            if (data.security.data.attributes.last_analysis_results.Spam404.result === "clean") {
                spam = "Not Found";
            } else {
                spam = "Found";
            }

            //safe browsing
            if (
                data.security &&
                data.security.data &&
                data.security.data.attributes &&
                data.security.data.attributes.last_analysis_results &&
                data.security.data.attributes.last_analysis_results["Google Safebrowsing"] &&
                data.security.data.attributes.last_analysis_results["Google Safebrowsing"].result
            ) {
                if (data.security.data.attributes.last_analysis_results["Google Safebrowsing"].result === "clean" && !isAdult(domain)) {
                    safe_Browsing = "Yes";
                }
                else {
                    safe_Browsing = "No";
                }
            } else {
                safe_Browsing = "Unknown"; // Handle missing data
            }

            // Registrant details
            registrantName = data.whois.WhoisRecord.registrant?.name ?? "N/A";
            registrantOrganization = data.whois.WhoisRecord.registrant?.organization ?? "N/A";
            registrantCountry = data.whois.WhoisRecord.registrant?.country ?? "N/A";
            registrantState = data.whois.WhoisRecord.registrant?.state ?? "N/A";
            registrantCity = data.whois.WhoisRecord.registrant?.city ?? "N/A";
            registrantStreet = data.whois.WhoisRecord.registrant?.street1 ?? "N/A";
            registrantPostalCode = data.whois.WhoisRecord.registrant?.postalCode ?? "N/A";
            registrantPhone = data.whois.WhoisRecord.registrant?.telephone ?? "N/A";
            registrantEmail = data.whois.WhoisRecord.contactEmail || "N/A";

            // Update DOM elements

            //key details
            DomainAge_div.innerHTML = `${DomainAge}`;
            website_type_div.innerHTML = `${website_type}`;
            alexaRank_div.innerHTML = `${alexaRank}`;

            //details
            organization_div.innerHTML = `${websiteName}`;
            organizationCountry_div.innerHTML = `${organizationCountry}`;
            organizationCity_div.innerHTML = `${organizationCity}`;
            organizationState_div.innerHTML = `${organizationState}`;
            officialWebsite_div.innerHTML = `${officialWebsite}`

            //webdetails
            websiteName_div.innerHTML = `${websiteName}`;
            domainExtension_div.innerHTML = `${domainExtension}`;
            Reg_Web_div.innerHTML = `${Reg_Web}`;
            IP_div.innerHTML = `${IP}`;
            ssl_cert_div.innerHTML = `${ssl_cert}`;
            validation_div.innerHTML = `${validTill}`
            reputation_div.innerHTML = `${reputation}`;



            //security
            malware_div.innerHTML = `${malware}`;
            phishing_div.innerHTML = `${phishing}`;
            scam_div.innerHTML = `${scam}`;
            spam_div.innerHTML = `${spam}`;
            safe_Browsing_div.innerHTML = `${safe_Browsing}`;

            //registrant
            registrantName_div.innerHTML = `${registrantName}`;
            registrantOrganization_div.innerHTML = `${registrantOrganization}`;
            registrantCountry_div.innerHTML = `${registrantCountry}`;
            registrantState_div.innerHTML = `${registrantState}`;
            registrantCity_div.innerHTML = `${registrantCity}`;
            registrantStreet_div.innerHTML = `${registrantStreet}`;
            registrantPostalCode_div.innerHTML = `${registrantPostalCode}`;
            registrantPhone_div.innerHTML = `${registrantPhone}`;
            registrantEmail_div.innerHTML = `${registrantEmail}`;

            //next update

            verifyHttp(domain);

            // Check for unsafe conditions
            checkSafetyAndAlert();
            createDisc();
            showResultDiv();
        }
    } catch (error) {
        console.error("Error fetching data:", error); // log error
        blank_div.innerHTML = `<p class="errordiv"> Error: ${error.message}</p>`;
        showErrorDiv();
    }
}

hideLoadingDiv()
hideResultDiv();