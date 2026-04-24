console.log("DNS CHECKER LOADED");

// Extract domain
function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return null;
    }
}

// Extract root domain
function getRootDomain(domain) {
    if (!domain) return null;
    const parts = domain.split(".");
    return parts.slice(-2).join(".");
}

// Trusted domains
const trustedDomains = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "razorpay.com",
    "cloudflare.com",
    "youtube.com",
    "mongodb.com",
    "github.com",
    "stackoverflow.com"
];

// Similarity check
function similarity(a, b) {
    let matches = 0;
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
        if (a[i] === b[i]) matches++;
    }
    return matches / Math.max(a.length, b.length);
}

// Entropy check
function calculateEntropy(str) {
    let uniqueChars = new Set(str);
    return uniqueChars.size / str.length;
}

// MAIN FUNCTION
function checkDNS(url) {

    const domain = getDomain(url);
    const rootDomain = getRootDomain(domain);

    console.log("Checking domain:", domain);

    if (!domain) {
        return { status: "safe", score: 100 };
    }

    // STEP 1: '@' phishing 
    if (url.includes("@")) {
        return { status: "spoofed", score: 5 };
    }

    // STEP 2: suspicious keywords + hyphen 
    if (
        (url.includes("login") ||
         url.includes("secure") ||
         url.includes("verify")) &&
        domain.includes("-")
    ) {
        return { status: "spoofed", score: 10 };
    }

    // STEP 3: trusted domain 
    if (rootDomain && trustedDomains.some(d => domain.endsWith(d))) {
        return { status: "safe", score: 95 };
    }

    // STEP 4: subdomain spoof
    if (domain && rootDomain) {
        for (let legit of trustedDomains) {
            if (domain.includes(legit) && !rootDomain.includes(legit)) {
                return { status: "spoofed", score: 10 };
            }
        }
    }

    // STEP 5: typo detection 
    if (rootDomain) {
        for (let legit of trustedDomains) {
            const sim = similarity(rootDomain, legit);
            if (sim > 0.75 && rootDomain !== legit) {
                return { status: "spoofed", score: 20 };
            }
        }
    }

    // ───── STEP 6: entropy ─────
    if (rootDomain) {
        const name = rootDomain.split(".")[0];
        const entropy = calculateEntropy(name);

        if (entropy > 0.6 && name.length > 6) {
            return { status: "suspicious", score: 30 };
        }
    }

    // ───── STEP 7: feature-based ─────
    const features = extractFeatures(url);

    let risk = 0;

    if (features.hasAtSymbol) risk += 50;
    if (features.numDots > 4) risk += 0;
    if (features.hasNumbers && features.length > 60) risk += 15;

    let status = "safe";

    if (risk >= 50) status = "spoofed";
    else if (risk >= 25) status = "suspicious";

    // ML integration
    const mlResult = predictML(features);

    if (mlResult === "suspicious" && status === "safe") {
        status = "suspicious";
    }

    // aggressive mode (your original behavior)
    if (status === "suspicious") {
        status = "spoofed";
    }

    return {
        status,
        score: Math.max(0, Math.min(100, 100 - risk))
    };
}