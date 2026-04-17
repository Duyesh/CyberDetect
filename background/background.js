//Runs when tab is updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {

    //Check if page is fully loaded
    if (changeInfo.status === "complete" && tab.url)
        {        
        console.log("User visited:", tab.url);
    }
});