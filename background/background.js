console.log("Background script running");

// Listen for tab updates (navigation start)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    if (changeInfo.status === "loading" && tab.url) {

        // Ignore internal pages
        if (
            tab.url.startsWith("chrome://") ||
            tab.url.startsWith("edge://") ||
            tab.url.startsWith("about:")
        ) return;

        // Ask content script to evaluate URL
        chrome.tabs.sendMessage(tabId, {
            type: "CHECK_URL",
            url: tab.url
        }, (response) => {

            if (chrome.runtime.lastError) {
                return; // content script not ready yet
            }

            if (!response) return;

            if (response.status === "spoofed") {

                // Redirect instantly to blocked UI
                chrome.tabs.update(tabId, {
                    url: chrome.runtime.getURL("blocked.html")
                });
            }
        });
    }
});