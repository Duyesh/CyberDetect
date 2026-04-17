window.addEventListener("load", async () => {

    const url = window.location.href;

    console.log("Checking URL:", url);

    const result = checkDNS(url);

    console.log("DNS Result:", result);

    // Safety check
    if (!result || !result.status) {
        console.error("DNS check failed:", result);
        return;
    }

    // FUNCTION FIRST (IMPORTANT)
    async function getIP() {
        try {
            const res = await fetch("https://api.ipify.org?format=json");
            const data = await res.json();
            return data.ip;
        } catch {
            return "Unknown";
        }
    }

    // BLOCK if spoofed
    if (result.status === "spoofed") {

        const ip = await getIP();

        const overlay = document.createElement("div");

        overlay.classList.add("cd-overlay");

        overlay.innerHTML = `
            <div class="cd-header">
                <img src="${chrome.runtime.getURL('assets/icon.png')}"/>
                <span>CyberDetect</span>
            </div>

            <div class="cd-main">

                <h1 class="cd-title">⚠️ Unsafe Website Blocked</h1>

                <p class="cd-message">
                    CyberDetect AI has detected this website as a potential phishing or spoofing threat.
                    Access has been restricted to protect your system, identity, and sensitive data.
                </p>

                <div class="cd-info">
                    <div><strong>URL:</strong> ${url}</div>
                    <div><strong>IP Address:</strong> ${ip}</div>
                </div>

                <div class="cd-buttons">
                    <button class="safe-btn">Go Back to Safety</button>
                    <button class="danger-btn">Continue Anyway</button>
                </div>

            </div>
        `;

        const style = document.createElement("style");

        style.innerHTML = `
        .cd-overlay {
            position: fixed !important;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            background: #f8fafc;
            z-index: 2147483647;
            font-family: 'Segoe UI', sans-serif;
            color: #1e293b;
        }

        /* BIGGER HEADER */
        .cd-header {
            position: absolute;
            top: 30px;
            left: 50px;
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .cd-header img {
            width: 60px; 
        }

        .cd-header span {
            font-size: 28px;
            font-weight: 700;
        }

        /*  FULL PAGE UTILIZATION */
        .cd-main {
            height: 100%;
            width: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            gap: 35px;   
            text-align: center;
            padding: 60px;
        }

        /*  BIG TITLE */
        .cd-title {
            font-size: 48px;
            color: #dc2626;
        }

        /* BETTER TEXT SPACING */
        .cd-message {
            font-size: 20px;
            max-width: 800px;
            line-height: 1.6;
            color: #475569;
        }

        /* INFO BOX */
        .cd-info {
            font-size: 18px;
            color: #334155;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        /* BUTTONS SPACING */
        .cd-buttons {
            display: flex;
            gap: 25px;
            margin-top: 20px;
        }

        .cd-buttons button {
            padding: 16px 32px;
            font-size: 16px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-weight: 600;
        }

        /* COLORS */
        .safe-btn {
            background: #2563eb;
            color: white;
        }

        .danger-btn {
            background: #dc2626;
            color: white;
        }
        `;

        document.head.appendChild(style);
        document.body.appendChild(overlay);

        return;
    }

    // Warning for suspicious
    if (result.status === "suspicious") {
        alert("Warning: This site looks suspicious!");
    }

    // Banner
    const banner = document.createElement("div");

    banner.innerText = `CyberDetect: ${result.status.toUpperCase()} (Score: ${result.score})`;

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.padding = "12px";
    banner.style.color = "white";
    banner.style.fontSize = "16px";
    banner.style.textAlign = "center";
    banner.style.zIndex = "2147483647";
    banner.style.fontWeight = "bold";

    if (result.status === "safe") {
        banner.style.backgroundColor = "green";
    } else {
        banner.style.backgroundColor = "orange";
    }

    document.body.appendChild(banner);

});