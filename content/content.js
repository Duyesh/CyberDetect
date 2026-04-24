window.addEventListener("load", async () => {

    if (sessionStorage.getItem("cd_bypass") === "true") {
        console.log("Bypass active — allowing page");

        sessionStorage.removeItem("cd_bypass");
        return;
    }

    const url = window.location.href;
    const hostname = window.location.hostname;
    // Skip blocker on Gmail (let gmailScanner handle it)
    const isEmailClient =
        hostname.includes("mail.google.com") ||
        hostname.includes("mail.yahoo.com") ||
        hostname.includes("outlook.live.com") ||
        hostname.includes("outlook.office.com") ||
        hostname.includes("mail.rediff.com");

    if (isEmailClient) {
        console.log("Email client detected — skipping content.js logic");
        return;
    }

    const result =await checkDNS(url);
    let emailResult = { status: "safe", score: 100 };

    // Only run email check on relevant pages
    if (
         document.body &&
        (
            document.body.innerText.includes("verify") ||
            document.body.innerText.includes("account") ||
            document.body.innerText.includes("password") ||
            document.body.innerText.includes("register") ||
            document.body.innerText.includes("login")
        )
    ) {
        emailResult = checkEmail();
    }

    let finalStatus = result.status;
    let finalScore = result.score;
    
    const rules = [
        {
            condition: () => result.status === "spoofed",
            action: () => "spoofed"
        },
        {
            condition: () => emailResult.status === "spoofed",
            action: () => "suspicious"
        },
        {
            condition: () =>
                result.status === "suspicious" ||
                emailResult.status === "suspicious",
            action: () => "suspicious"
        }
    ];

    // evaluate rules
    for (const rule of rules) {
        if (rule.condition()) {
            finalStatus = rule.action();
            break;
        }
    }

    function showTopIndicator(status, score) {

        const old = document.querySelector(".cd-indicator");
        if (old) old.remove();

        const el = document.createElement("div");
        el.className = "cd-indicator";

        const map = {
            safe:        { text: "SAFE",        color: "#16a34a" },
            suspicious:  { text: "SUSPICIOUS",  color: "#f97316" },
            spoofed:     { text: "BLOCKED",     color: "#dc2626" }
        };

        const cfg = map[status] || map.safe;

        el.innerText = `CyberDetect: ${cfg.text} (${score})`;

        Object.assign(el.style, {
            position: "fixed",
            top: "8px",
            left: "10px",
            padding: "6px 10px",
            background: cfg.color,
            color: "white",
            fontSize: "12px",
            borderRadius: "6px",
            zIndex: "999999999",
            fontWeight: "600",
            boxShadow: "0 2px 6px rgba(0,0,0,0.2)",
            opacity: "0.95"
        });

        document.body.appendChild(el);

        setTimeout(() => {
            el.style.transition = "opacity 0.4s";
            el.style.opacity = "0";
        }, 4000);
    }

    let confidence = "Low";

    if (finalScore > 70) confidence = "High";
    else if (finalScore > 40) confidence = "Medium";

    chrome.storage.local.get("cyberdetect_history", (data) => {

        let history = data.cyberdetect_history || [];

        // add new entry at top
        history.unshift({
            confidence: confidence,
            url: window.location.href,
            status: finalStatus,
            score: finalScore,
            time: new Date().toLocaleTimeString()
        });
                
        // keep only last 5
        history = history.slice(0, 5);

        chrome.storage.local.set({
            cyberdetect_last: history[0],
            cyberdetect_history: history
        });
    });

    console.log("Email Result:", emailResult);

    if (!result || !result.status) return;

    async function getIP() {
        try {
            const res = await fetch("https://api.ipify.org?format=json");
            const data = await res.json();
            return data.ip;
        } catch {
            return "Unknown";
        }
    }

    if (finalStatus === "spoofed" || finalStatus === "suspicious") {

        const ip = await getIP();

        const overlay = document.createElement("div");
        overlay.classList.add("cd-overlay");

        overlay.innerHTML = `
            <div class="cd-alert-bar">
                This site has been blocked for your safety
            </div>

            <div class="cd-header">
                <img src="${chrome.runtime.getURL('assets/icon.png')}"/>
                <span>CyberDetect</span>
            </div>

            <div class="cd-main">

                <!-- LEFT -->
                <div class="cd-left">
                    <img class="cd-big-icon" src="${chrome.runtime.getURL('assets/danger.png')}" />
                </div>

                <!-- RIGHT -->
                <div class="cd-right">

                    <h1 class="cd-title">
                        ${finalStatus === "spoofed" ? "Access Blocked" : "Suspicious Website"}
                    </h1>

                    <div class="cd-body">
                        <p class="cd-message">
                            ${
                                finalStatus === "spoofed"
                                ? "This website has been identified as a high-risk phishing or spoofing threat."
                                : "This website appears suspicious and may not be safe to use."
                            }
                        </p>

                        <div class="cd-info-box">
                            <p><strong>URL:</strong> ${url}</p>
                            <p><strong>IP Address:</strong> ${ip}</p>
                        </div>
                    </div>

                    <div class="cd-buttons">
                        <button class="safe-btn" onclick="window.location.href='https://google.com'">
                            Go Back
                        </button>

                        <button class="danger-btn" onclick="
                            sessionStorage.setItem('cd_bypass', 'true');
                            window.location.reload();
                        ">
                            Continue (Unsafe)
                        </button>
                    </div>

                </div>

            </div>
        `;

        const style = document.createElement("style");

        style.innerHTML = `
        html, body {
            margin: 0;
            overflow: hidden !important;
        }

        .cd-overlay {
            position: fixed !important;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;

            display: flex;
            flex-direction: column;

            background: #f8fafc;
            z-index: 2147483647;
            font-family: 'Segoe UI', sans-serif;
        }

        /* ALERT */
        .cd-alert-bar {
            width: 100%;
            background: #fee2e2;
            color: #991b1b;
            text-align: center;
            padding: 14px;
            font-weight: 700;
        }

        /* HEADER (UNCHANGED) */
        .cd-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin: 20px 40px;
        }

        .cd-header img {
            width: 70px;
        }

        .cd-header span {
            font-size: 28px;
            font-weight: 700;
        }

        /* MAIN */
        .cd-main {
            flex: 1;
            display: flex;
        }

        /* LEFT */
        .cd-left {
            width: 45%;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .cd-big-icon {
            width: 240px;
            max-width: 80%;
        }

        /* RIGHT = MAIN BOX */
        .cd-right {
            width: 55%;

            background: #fee2e2;
            border-radius: 18px;

            padding: 50px;

            display: flex;
            flex-direction: column;

            justify-content: space-between;   

            box-shadow: 0 25px 60px rgba(0,0,0,0.18);

            margin-right: 50px;
            margin-bottom: 50px
        }

        /* TITLE */
        .cd-title {
            font-size: 46px;
            color: #b91c1c;
            margin: 0;
        }

        /* BODY CENTER */
        .cd-body {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 20px;
            text-align: center;
        }

        /* MESSAGE */
        .cd-message {
            font-size: 18px;
            line-height: 1.7;
            max-width: 600px;
            color: #030810;
        }

        /* INFO */
        .cd-info-box {
            width: 100%;
            max-width: 550px;

            background: #f1f5f9;
            padding: 18px;
            border-radius: 12px;

            text-align: left;
        }

        /* BUTTONS */
        .cd-buttons {
            display: flex;
            justify-content: center;
            gap: 20px;
        }

        .cd-buttons button {
            padding: 14px 28px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: 0.2s;
        }

        .safe-btn {
            background: #2563eb;
            color: white;
        }

        .danger-btn {
            background: #dc2626;
            color: white;
        }

        .cd-buttons button:hover {
            transform: scale(1.05);
        }

        @keyframes cd-pulse-shake {
            0%   { transform: scale(1) translateX(0); }

            15%  { transform: scale(1.15) translateX(-3px); }
            30%  { transform: scale(1.25) translateX(3px); }

            45%  { transform: scale(1.18) translateX(-2px); }
            60%  { transform: scale(1.22) translateX(2px); }

            75%  { transform: scale(1.1) translateX(-1px); }
            90%  { transform: scale(1.05) translateX(1px); }

            100% { transform: scale(1) translateX(0); }
        }

        .cd-big-icon {
            width: 240px;
            max-width: 80%;

            animation: cd-pulse-shake 2.2s ease-out;
        }
        `;

        document.head.appendChild(style);
        document.body.appendChild(overlay);

        return;
    }

    if (finalStatus === "safe") {
        showTopIndicator(finalStatus, finalScore);
    }

});