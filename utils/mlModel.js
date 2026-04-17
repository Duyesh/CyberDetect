let model = null;

// Load model (we will paste JSON manually)
const weights = [0.5433529656289018, 3.4787820178595266, -2.882117111051364, 2.2004500811395706, 0.9110251222436143];
const intercept = -4.897618055981687;

function predictML(features) {

    const x = [
        features.length,
        features.hasNumbers ? 1 : 0,
        features.numDots,
        features.hasHyphen ? 1 : 0,
        features.hasAtSymbol ? 1 : 0
    ];

    let score = intercept;

    for (let i = 0; i < weights.length; i++) {
        score += weights[i] * x[i];
    }

    // sigmoid function
    const probability = 1 / (1 + Math.exp(-score));

    return probability > 0.4 ? "suspicious" : "safe";
}