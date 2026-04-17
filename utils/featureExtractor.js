// Extract features from URL

function extractFeatures(url) {

    const features = {
        length: url.length,
        hasNumbers: /\d/.test(url),
        numDots: (url.match(/\./g) || []).length,
        hasHyphen: url.includes("-"),
        hasAtSymbol: url.includes("@")
    };

    return features;
}