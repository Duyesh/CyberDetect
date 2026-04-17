window.addEventListener("load", async () => {

    const url = window.location.href;
    const result = checkDNS(url);

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

    if (result.status === "spoofed") {

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

                    <h1 class="cd-title">Access Blocked</h1>

                    <div class="cd-body">
                        <p class="cd-message">
                            This website has been identified as a potential phishing or spoofing threat.
                            CyberDetect prevented access to protect your data and credentials.
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

                        <button class="danger-btn" onclick="window.location.reload()">
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

            justify-content: space-between;   /* 🔥 layout control */

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

    if (result.status === "suspicious") {
        alert("Warning: This site looks suspicious!");
    }

});