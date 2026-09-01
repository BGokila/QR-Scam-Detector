// Trained offline using scikit-learn LogisticRegression on the
// Phishing-Dataset (GregaVrbancic/Phishing-Dataset, dataset_small.csv — ~58,600 URLs).
// Only URL-string-computable features were used (no WHOIS/DNS/TLS lookups),
// so this runs fully client-side with zero network calls.
// Test accuracy on a held-out 20% split (11,729 URLs): 85.6%
window.ML_MODEL = {"features": ["qty_dot_url", "qty_hyphen_url", "qty_underline_url", "qty_slash_url", "qty_questionmark_url", "qty_equal_url", "qty_at_url", "qty_and_url", "qty_exclamation_url", "qty_tilde_url", "qty_percent_url", "length_url", "qty_dot_domain", "qty_hyphen_domain", "qty_vowels_domain", "domain_length", "domain_in_ip", "server_client_domain", "qty_redirects", "url_shortened"], "mean": [2.2901568761190214, 0.4583510955750703, 0.17422627674993604, 1.9408304203256885, 0.014621877397902635, 0.31624605678233436, 0.03333617529201125, 0.21834768522465683, 0.004497399607809703, 0.004881064029329013, 0.16552988319549833, 45.17682666894024, 1.8012831443430812, 0.13383493903998636, 5.447310086111348, 18.08466194901526, 0.003538238554011425, 0.0033890357234205816, 0.3008568505413931, 0.008334043823002813], "scale": [1.4924076364867982, 1.3376377807471793, 0.8154587815604254, 2.0426006134087213, 0.14304352513568355, 1.1761554568223866, 0.3033006193622564, 1.149692622520885, 0.10748790682024367, 0.09965006514481183, 2.1916960865995585, 56.12321731990078, 0.7960218833888412, 0.47119812751355167, 2.729666182693624, 7.278952911311255, 0.05937776875186034, 0.05811669433378454, 0.812847714831534, 0.0909097769030143], "coef": [1.1267973774754036, -0.7948813218134043, -0.24158127426221507, 1.872994982365049, -0.02808632482271979, 0.08052073858046377, 1.2375722308267338, -0.2561002427850206, -0.029094012210281052, -0.057184833898637974, -0.38110360005111715, 2.2646575430932434, -1.6003969148021586, 0.5827262839225928, -0.04111519457103609, 0.49646501431301465, 0.25043285930670406, 0.016791969959538987, -0.03681987088730064, 0.45305844888528274], "intercept": 1.0241945566709136, "test_accuracy": 0.8562, "train_size": 46916, "test_size": 11729};

// Extracts the same lexical features from a raw URL string that the model was trained on.
function extractUrlFeatures(rawUrl) {
    let url = rawUrl;
    let domain = "";
    try {
        let u = new URL(url.startsWith("http") ? url : "http://" + url);
        domain = u.hostname;
    } catch (e) {
        domain = url.split("/")[0];
    }

    const count = (str, ch) => (str.match(new RegExp("\\" + ch, "g")) || []).length;
    const vowels = (str) => (str.match(/[aeiouAEIOU]/g) || []).length;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const shortenerList = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rb.gy"];

    return [
        count(url, "."),                                   // qty_dot_url
        count(url, "-"),                                    // qty_hyphen_url
        count(url, "_"),                                    // qty_underline_url
        count(url, "/"),                                    // qty_slash_url
        count(url, "?"),                                    // qty_questionmark_url
        count(url, "="),                                    // qty_equal_url
        count(url, "@"),                                    // qty_at_url
        count(url, "&"),                                    // qty_and_url
        count(url, "!"),                                    // qty_exclamation_url
        count(url, "~"),                                    // qty_tilde_url
        count(url, "%"),                                    // qty_percent_url
        url.length,                                         // length_url
        count(domain, "."),                                 // qty_dot_domain
        count(domain, "-"),                                 // qty_hyphen_domain
        vowels(domain),                                     // qty_vowels_domain
        domain.length,                                      // domain_length
        ipPattern.test(domain) ? 1 : 0,                      // domain_in_ip
        /server|client/i.test(domain) ? 1 : 0,               // server_client_domain
        0,                                                   // qty_redirects (not knowable client-side without a request)
        shortenerList.some(s => domain.includes(s)) ? 1 : 0  // url_shortened
    ];
}

// Returns phishing probability 0-1 using the trained logistic regression weights.
function mlPredictPhishing(rawUrl) {
    const model = window.ML_MODEL;
    const x = extractUrlFeatures(rawUrl);
    let z = model.intercept;
    for (let i = 0; i < model.features.length; i++) {
        const scaled = (x[i] - model.mean[i]) / model.scale[i];
        z += model.coef[i] * scaled;
    }
    const prob = 1 / (1 + Math.exp(-z));
    return prob; // 0-1
}
