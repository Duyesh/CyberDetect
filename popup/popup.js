console.log("Popup JS running");

document.addEventListener("DOMContentLoaded", () => {

    const statusBox = document.getElementById("statusBox");
    const details = document.getElementById("details");

    chrome.storage.local.get("cyberdetect_last", (data) => {

        console.log("Storage data:", data);

        if (!data || !data.cyberdetect_last) {
            statusBox.innerText = "No Data Found";
            return;
        }

        const { url, status, score, time } = data.cyberdetect_last;

        // Status text
        statusBox.innerText = status.toUpperCase();

        // Reset class first (important)
        statusBox.className = "status";
        statusBox.classList.add(status);

        // Details
        details.innerHTML = `
            <div><strong>URL:</strong> ${url}</div>
            <div><strong>Score:</strong> ${score}</div>
            <div><strong>Time:</strong> ${time}</div>
        `;
    });

});

const historyDiv = document.getElementById("history");

chrome.storage.local.get("cyberdetect_history", (data) => {

    const history = data.cyberdetect_history || [];

    if (history.length === 0) {
        historyDiv.innerHTML = "<div>No history</div>";
        return;
    }

    historyDiv.innerHTML = history.map(item => `
        <div style="
            margin-top:8px;
            padding:6px;
            border-radius:6px;
            background:#e2e8f0;
            font-size:11px;
        ">
            <div><strong>${item.status.toUpperCase()}</strong> (${item.score})</div>
            <div>${item.url}</div>
        </div>
    `).join("");
});