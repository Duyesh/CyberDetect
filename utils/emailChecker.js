// ============================================================
//  CyberDetect – Email Spoofing Detection Engine
//  utils/emailChecker.js
//
//  ML weights trained on: Kaggle Phishing Email Dataset
//  (naserabdullahalam/phishing-email-dataset)
//
//  TO UPDATE WEIGHTS: Run ml/train_email_model.py
//  and replace EMAIL_ML_WEIGHTS + EMAIL_ML_INTERCEPT below.
//
//  Returns: { status: "safe" | "suspicious" | "spoofed", score: number }
// ============================================================

console.log("Email Checker Loaded ✅");

// ────────────────────────────────────────────────────────────
//  ML WEIGHTS  (trained via train_email_model.py)
//
//   REPLACE THESE after running the training script.
//
//  Feature Order:
//  [0] urgencyScore          – urgency phrases density
//  [1] credentialScore       – otp/pin/password density
//  [2] rewardScore           – prize/gift/winner density
//  [3] authorityScore        – bank/irs/government density
//  [4] urlCountNorm          – number of http links
//  [5] hasAtSymbol           – @ in body (not email addr)
//  [6] exclamationRatio      – !! count normalized
//  [7] capsRatio             – UPPERCASE ratio
//  [8] textLengthNorm        – log-normalized text length
//  [9] totalSuspiciousNorm   – all phishing words combined
// ────────────────────────────────────────────────────────────

// ↓↓↓ PASTE OUTPUT FROM train_email_model.py HERE ↓↓↓
const EMAIL_ML_WEIGHTS   = [8.710023, -2.88252, 2.271535, -2.899699, -4.091951, -0.372015, 4.543527, 8.223207, -0.726214, 2.599669];
const EMAIL_ML_INTERCEPT = -1.643704;
// ↑↑↑ ─────────────────────────────────────────────── ↑↑↑


// ────────────────────────────────────────────────────────────
//  TRUSTED SENDER DOMAINS
// ────────────────────────────────────────────────────────────
const TRUSTED_SENDER_DOMAINS = [
    "google.com", "gmail.com",
    "paypal.com",
    "amazon.com", "amazon.in",
    "microsoft.com", "outlook.com", "hotmail.com",
    "apple.com", "icloud.com",
    "facebook.com", "meta.com",
    "twitter.com", "x.com",
    "github.com",
    "razorpay.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com"
];

// ────────────────────────────────────────────────────────────
//  KEYWORD LISTS
// ────────────────────────────────────────────────────────────
const URGENCY_WORDS = [
    "verify", "confirm", "suspended", "unusual", "unauthorized",
    "expire", "immediate", "action required", "click here",
    "limited time", "act now", "your account", "access restricted"
];

const CREDENTIAL_WORDS = [
    "password", "otp", "pin", "cvv", "credit card", "ssn",
    "social security", "bank account", "login", "signin",
    "username", "credentials", "re-enter"
];

const REWARD_WORDS = [
    "won", "winner", "prize", "gift", "free", "claim",
    "selected", "lottery", "reward", "offer", "congratulations"
];

const AUTHORITY_WORDS = [
    "irs", "rbi", "government", "official", "bank", "paypal",
    "amazon", "microsoft", "apple", "tax", "refund", "department"
];

// ────────────────────────────────────────────────────────────
//  SUSPICIOUS URL PATH PATTERNS
// ────────────────────────────────────────────────────────────
const SUSPICIOUS_PATH_PATTERNS = [
    /verify[-_]?account/i,
    /confirm[-_]?email/i,
    /reset[-_]?password/i,
    /update[-_]?billing/i,
    /login[-_]?redirect/i,
    /auth[-_]?token/i,
    /secure[-_]?login/i,
    /email[-_]?verify/i,
    /account[-_]?suspended/i,
    /redirect\?url=/i,
    /r\?u=https?:/i,
    /go\?url=/i
];

// ────────────────────────────────────────────────────────────
//  SAFE EARLY EXIT
//  Returns true if this page should NOT be email-checked.
//  (browser internal pages, empty pages, etc.)
// ────────────────────────────────────────────────────────────
function shouldSkipEmailCheck() {
    const url = window.location.href;

    // Skip all browser internal pages
    if (
        url.startsWith("chrome://") ||
        url.startsWith("edge://")   ||
        url.startsWith("about:")    ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("moz-extension://")
    ) {
        return true;
    }

    // Skip if body doesn't exist yet
    if (!document.body) {
        return true;
    }

    return false;
}

// ────────────────────────────────────────────────────────────
//  FEATURE EXTRACTION  (mirrors Python extract_features())
// ────────────────────────────────────────────────────────────
function extractEmailFeatures() {

    // Safe fallback if body is missing
    const rawText = (document.body && document.body.innerText) ? document.body.innerText : "";
    const text    = rawText.toLowerCase();

    // [0] Urgency score
    const urgency    = URGENCY_WORDS.filter(w => text.includes(w)).length;

    // [1] Credential score
    const credential = CREDENTIAL_WORDS.filter(w => text.includes(w)).length;

    // [2] Reward score
    const reward     = REWARD_WORDS.filter(w => text.includes(w)).length;

    // [3] Authority score
    const authority  = AUTHORITY_WORDS.filter(w => text.includes(w)).length;

    // [4] URL count
    const urls = (text.match(/https?:\/\//g) || []).length;

    // [5] @ symbol used suspiciously in body
    const atInBody = /\s@\s|\s@\w|@http/i.test(text) ? 1 : 0;

    // [6] Exclamation ratio
    const exclamations = Math.min(rawText.split("!").length - 1, 10) / 10.0;

    // [7] Caps ratio
    const alpha     = rawText.replace(/[^a-zA-Z]/g, "");
    const capsRatio = alpha.length > 0
        ? rawText.replace(/[^A-Z]/g, "").length / alpha.length
        : 0;

    // [8] Text length (log-normalized)
    const textLengthNorm = Math.log(rawText.length + 1) / 10.0;

    // [9] Total suspicious words (normalized)
    const totalSuspicious = urgency + credential + reward + authority;

    return [
        Math.min(urgency, 10)         / 10.0,   // [0]
        Math.min(credential, 10)      / 10.0,   // [1]
        Math.min(reward, 10)          / 10.0,   // [2]
        Math.min(authority, 10)       / 10.0,   // [3]
        Math.min(urls, 10)            / 10.0,   // [4]
        atInBody,                               // [5]
        exclamations,                           // [6]
        capsRatio,                              // [7]
        textLengthNorm,                         // [8]
        Math.min(totalSuspicious, 20) / 20.0    // [9]
    ];
}

// ────────────────────────────────────────────────────────────
//  DOM SIGNAL EXTRACTION
// ────────────────────────────────────────────────────────────
function extractDOMSignals() {
    const signals = {
        senderDomain:            null,
        hasTrackingPixel:        false,
        hasRedirectParam:        false,
        hasSuspiciousFormAction: false,
        formActionDomain:        null,
        suspiciousPath:          false
    };

    // Guard: body must exist
    if (!document.body) return signals;

    // mailto: sender domain
    try {
        const mailtoLink = document.querySelector("a[href^='mailto:']");
        if (mailtoLink) {
            const match = mailtoLink.getAttribute("href").match(/mailto:([^?&]+)/i);
            if (match) {
                const parts = match[1].toLowerCase().split("@");
                if (parts.length === 2) signals.senderDomain = parts[1];
            }
        }
    } catch (_) {}

    // 1×1 tracking pixels
    try {
        document.querySelectorAll("img").forEach(img => {
            const w   = img.getAttribute("width");
            const h   = img.getAttribute("height");
            const src = img.getAttribute("src") || "";
            if ((w === "1" || w === "0") && (h === "1" || h === "0")) {
                signals.hasTrackingPixel = true;
            }
            if (/track|pixel|beacon|open\b/i.test(src) && src.startsWith("http")) {
                signals.hasTrackingPixel = true;
            }
        });
    } catch (_) {}

    // Redirect params in URL
    try {
        const urlStr = window.location.href;
        if (/[?&](redirect|url|return|goto|next|redir)=/i.test(urlStr)) {
            signals.hasRedirectParam = true;
        }
    } catch (_) {}

    // Suspicious URL path
    try {
        const path = window.location.pathname + window.location.search;
        SUSPICIOUS_PATH_PATTERNS.forEach(p => {
            if (p.test(path)) signals.suspiciousPath = true;
        });
    } catch (_) {}

    // Form posting to external domain
    try {
        document.querySelectorAll("form[action]").forEach(form => {
            const action = form.getAttribute("action") || "";
            if (action.startsWith("http") || action.startsWith("//")) {
                try {
                    const actionDomain = new URL(action).hostname;
                    if (actionDomain && actionDomain !== window.location.hostname) {
                        signals.hasSuspiciousFormAction = true;
                        signals.formActionDomain = actionDomain;
                    }
                } catch (_) {}
            }
        });
    } catch (_) {}

    return signals;
}

// ────────────────────────────────────────────────────────────
//  SENDER DOMAIN SPOOF CHECK
// ────────────────────────────────────────────────────────────
function checkSenderDomainSpoof(senderDomain) {
    if (!senderDomain) return { spoofed: false };

    try {
        const getRoot    = d => d.split(".").slice(-2).join(".");
        const senderRoot = getRoot(senderDomain);
        const pageRoot   = getRoot(window.location.hostname.toLowerCase());

        const claimsTrusted = TRUSTED_SENDER_DOMAINS.some(d => senderRoot === d);
        if (claimsTrusted && senderRoot !== pageRoot) {
            return {
                spoofed: true,
                reason: `Sender claims ${senderDomain} but page is on ${window.location.hostname}`
            };
        }
    } catch (_) {}

    return { spoofed: false };
}

// ────────────────────────────────────────────────────────────
//  ML SIGMOID SCORER
// ────────────────────────────────────────────────────────────
function emailMLScore(featureVector) {
    try {
        let score = EMAIL_ML_INTERCEPT;
        for (let i = 0; i < EMAIL_ML_WEIGHTS.length; i++) {
            score += EMAIL_ML_WEIGHTS[i] * featureVector[i];
        }
        return 1 / (1 + Math.exp(-score));
    } catch (_) {
        return 0; // safe fallback
    }
}

// ────────────────────────────────────────────────────────────
//  MAIN FUNCTION  checkEmail()
//  Called from content.js after checkDNS().
//  Returns: { status: "safe"|"suspicious"|"spoofed", score }
// ────────────────────────────────────────────────────────────
function checkEmail() {

    // ── Safe early exit for internal/empty pages ──────────
    if (shouldSkipEmailCheck()) {
        console.log("[EmailChecker] Skipped — internal or empty page.");
        return { status: "safe", score: 100 };
    }

    // ── Extract signals (all wrapped in try-catch) ────────
    let features   = new Array(10).fill(0);  // safe default
    let domSignals = {
        senderDomain:            null,
        hasTrackingPixel:        false,
        hasRedirectParam:        false,
        hasSuspiciousFormAction: false,
        formActionDomain:        null,
        suspiciousPath:          false
    };
    let senderCheck = { spoofed: false };

    try { features    = extractEmailFeatures();              } catch (e) { console.warn("[EmailChecker] Feature extraction failed:", e.message); }
    try { domSignals  = extractDOMSignals();                 } catch (e) { console.warn("[EmailChecker] DOM signal extraction failed:", e.message); }
    try { senderCheck = checkSenderDomainSpoof(domSignals.senderDomain); } catch (e) { console.warn("[EmailChecker] Sender check failed:", e.message); }

    console.log("[EmailChecker] Feature vector:", features);
    console.log("[EmailChecker] DOM signals:", domSignals);

    // ── Hard-fail rules ───────────────────────────────────

    // Rule 1: Sender domain mismatch with a trusted brand
    if (senderCheck.spoofed) {
        console.warn("[EmailChecker] SPOOFED — sender domain mismatch:", senderCheck.reason);
        return { status: "spoofed", score: 5 };
    }

    // Rule 2: Form posts to external domain
    if (domSignals.hasSuspiciousFormAction) {
        console.warn("[EmailChecker] SPOOFED — external form action:", domSignals.formActionDomain);
        return { status: "spoofed", score: 8 };
    }

    // ── ML probability decision ───────────────────────────
    const mlProb   = emailMLScore(features);
    const safeScore = Math.round((1 - mlProb) * 100);

    console.log("[EmailChecker] ML probability:", mlProb.toFixed(4), "| Safe score:", safeScore);

    if (mlProb >= 0.65) {
        return { status: "spoofed",    score: safeScore };
    }

    if (mlProb >= 0.40) {
        return { status: "suspicious", score: safeScore };
    }

    if (domSignals.hasTrackingPixel) {
        return { status: "suspicious", score: 55 };
    }

    return { status: "safe", score: 90 };
}