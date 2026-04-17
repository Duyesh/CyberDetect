// DNS Analysis Engine
console.log("NEW DNS CHECKER LOADED");
// Extract domain from URL
function getDomain(url) {
    try {
        return new URL(url).hostname.toLowerCase();
    } catch {
        return null;
    }
}

// Extract root domain (example: login.paypal.com → paypal.com)
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

// Similarity check (typo detection)
function similarity(a, b) {
    let matches = 0;

    for (let i = 0; i < Math.min(a.length, b.length); i++) {
        if (a[i] === b[i]) matches++;
    }

    return matches / Math.max(a.length, b.length);
}

// Entropy check (random-looking domains)
function calculateEntropy(str) {
    let uniqueChars = new Set(str);
    return uniqueChars.size / str.length;
}

//  MAIN FUNCTION
function checkDNS(url) {

    const domain = getDomain(url);
    const rootDomain = getRootDomain(domain);

    console.log("Checking domain:", domain);

    // STEP 0: STRONG PHISHING RULES

    // Try detecting @ from multiple sources
    const rawUrl = document.URL || window.location.href;

    // Direct check
    if (rawUrl.includes("@")) {
        return {
            status: "spoofed",
            score: 5
        };
    }

    //  Suspicious mismatch between URL and domain
    if (url.includes("@") && domain && !url.includes(domain)) {
        return {
            status: "spoofed",
            score: 5
        };
    }

    // Detect suspicious mismatch patterns
    if (url.includes("login") || url.includes("secure") || url.includes("verify")) {
        if (domain && domain.includes("-")) {
            return {
                status: "spoofed",
                score: 10
            };
        }
    }

    //  STEP 1: Trusted domain check
    if (rootDomain && trustedDomains.some(d => rootDomain.endsWith(d))) {
        return { status: "safe", score: 95 };
    }

    //  STEP 2: Subdomain attack
    if (domain && rootDomain) {
        for (let legit of trustedDomains) {
            if (domain.includes(legit) && !rootDomain.endsWith(legit)) {
                return { status: "spoofed", score: 10 };
            }
        }
    }

    //  STEP 3: Typo detection
    if (rootDomain) {
        for (let legit of trustedDomains) {
            const sim = similarity(rootDomain, legit);

            if (sim > 0.75 && rootDomain !== legit) {
                return { status: "spoofed", score: 20 };
            }
        }
    }

    //  STEP 4: Entropy detection
    if (rootDomain) {
        const name = rootDomain.split(".")[0];
        const entropy = calculateEntropy(name);

        if (entropy > 0.6 && name.length > 6) {
            return { status: "suspicious", score: 30 };
        }
    }

    //  STEP 5: Feature-based analysis
    const features = extractFeatures(url);

    let risk = 0;

    if (features.hasAtSymbol) risk += 50;
    if (features.numDots > 4) risk += 20;
    if (features.hasNumbers && features.length > 60) risk += 15;

    // Base status
    let status = "safe";

    if (risk >= 50) {
        status = "spoofed";
    } else if (risk >= 25) {
        status = "suspicious";
    }

    //  STEP 6: ML integration
    const mlResult = predictML(features);

    if (mlResult === "suspicious" && status === "safe") {
        status = "suspicious";
    }

    // FINAL DECISION
    if (status === "suspicious") {
        status = "spoofed"; // AGGRESSIVE MODE
    }

    return {
        status,
        score: 100 - risk
    };
}