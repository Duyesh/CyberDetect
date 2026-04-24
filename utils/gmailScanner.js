console.log("CyberDetect Gmail Scanner Loaded");

if (window.location.hostname.includes("mail.google.com")) {
    initGmailScanner();
}

const SELECTORS = {
    emailPane: ['div[role="main"]', '.AO'],
    senderName: ['.go span[email]', '.gD'],
    senderEmail: ['span[email]', '.gD[email]'],
    replyTo: ['span[email][data-hovercard-id]'],
    subject: ['h2.hP'],
    body: ['div.a3s'],
    emailItem: ['div.adn', '.gs']
};

function queryAny(parent, list) {
    for (const sel of list) {
        try {
            const el = parent.querySelector(sel);
            if (el) return el;
        } catch {}
    }
    return null;
}

function queryAllAny(parent, list) {
    for (const sel of list) {
        try {
            const els = parent.querySelectorAll(sel);
            if (els.length > 0) return Array.from(els);
        } catch {}
    }
    return [];
}

function extractEmailData(container) {
    const data = {
        senderName: "",
        senderEmail: "",
        replyTo: "",
        subject: "",
        bodyText: "",
        links: []
    };

    try {
        const nameEl = queryAny(container, SELECTORS.senderName);
        if (nameEl) data.senderName = nameEl.innerText.trim();

        const emailEl = queryAny(container, SELECTORS.senderEmail);
        if (emailEl) {
            data.senderEmail =
                (emailEl.getAttribute("email") ||
                 emailEl.innerText || "").trim().toLowerCase();
        }

        const replyEl = queryAny(container, SELECTORS.replyTo);
        if (replyEl) {
            const rt = replyEl.getAttribute("email") || "";
            if (rt && rt !== data.senderEmail) data.replyTo = rt;
        }

        const subjectEl = queryAny(document, SELECTORS.subject);
        if (subjectEl) data.subject = subjectEl.innerText.trim();

        const bodyEl = queryAny(container, SELECTORS.body);
        if (bodyEl) {
            data.bodyText = bodyEl.innerText;

            bodyEl.querySelectorAll("a[href]").forEach(a => {
                const href = a.getAttribute("href") || "";
                if (href.startsWith("http")) data.links.push(href);
            });
        }

    } catch {}

    return data;
}

function analyzeEmail(data) {
    const result = {
        status: "safe",
        score: 100,
        reasons: []
    };

    const getRoot = d => (d || "").split(".").slice(-2).join(".");
    const senderDomain = data.senderEmail.split("@")[1] || "";
    const senderRoot = getRoot(senderDomain);

    if (data.replyTo) {
        const replyDomain = data.replyTo.split("@")[1] || "";
        const mismatch = getRoot(replyDomain) !== senderRoot;

        if (mismatch) {
            result.score -= 20;   // was 40 → too aggressive
            result.reasons.push("Reply-To mismatch");
        }
    }

    // reduce false positives for trusted platforms
    const SAFE_DOMAINS = ["google.com", "linkedin.com", "github.com"];

    if (SAFE_DOMAINS.some(d => senderDomain.includes(d))) {
        result.score += 15;
    }

    let suspiciousLinks = 0;
    data.links.forEach(link => {
        try {
            const linkDomain = new URL(link).hostname;
            if (!linkDomain.includes(senderRoot)) suspiciousLinks++;
        } catch {}
    });

    if (suspiciousLinks >= 2) {
        result.score -= suspiciousLinks * 8;
        result.reasons.push("External links detected");
    }

    try {
        const auth = checkAuthHeuristics(
            data.senderEmail,
            data.replyTo,
            data.links
        );

        if (auth.spfFail || auth.dmarcFail) {
            result.score -= 25;
            result.reasons.push("Authentication inconsistency");
        }

    } catch {}

    if (result.score <= 25) result.status = "spoofed";
    else if (result.score <= 55) result.status = "suspicious";
    else result.status = "safe";

    result.score = Math.max(0, Math.min(100, result.score));

    return result;
}

function showWarning(container, result) {
    const old = container.querySelector(".cd-gmail-warning");
    if (old) old.remove();

    let color = "#16a34a";
    let text = "SAFE";

    if (result.status === "suspicious") {
        color = "#f97316";
        text = "SUSPICIOUS";
    }

    if (result.status === "spoofed") {
        color = "#dc2626";
        text = "SPOOFED";
    }

    const box = document.createElement("div");
    box.className = "cd-gmail-warning";

    box.innerHTML = `
        <div style="
            background:${color};
            color:white;
            padding:10px;
            border-radius:8px;
            font-size:13px;
            margin-bottom:10px;
        ">
            CyberDetect: ${text} (${result.score})
        </div>
    `;

    container.insertBefore(box, container.firstChild);
}

function processEmail(container) {
    const data = extractEmailData(container);
    if (!data.senderEmail && !data.bodyText) return;

    const result = analyzeEmail(data);
    console.log("Gmail Result:", result);

    showWarning(container, result);
}

function initGmailScanner() {

    const processed = new WeakSet();
    let timer = null;

    const observer = new MutationObserver(() => {

        clearTimeout(timer);

        timer = setTimeout(() => {

            let container = null;

            for (const sel of SELECTORS.emailPane) {
                const el = document.querySelector(sel);
                if (el) { container = el; break; }
            }

            if (!container) return;

            const items = queryAllAny(container, SELECTORS.emailItem);
            const last = items[items.length - 1] || container;

            if (!processed.has(last)) {
                processed.add(last);
                setTimeout(() => processEmail(last), 500);
            }

        }, 300);
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}