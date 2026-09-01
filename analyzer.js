// ============================================================
// QR Shield Analyzer — heuristics + client-side ML + community
// reports + multi-language voice alerts, with a "why" breakdown.
// ============================================================

// ---- Multi-language voice/message strings ----
const LANG_STRINGS = {
    en: {
        code: "en-US",
        safe: "The link appears safe to visit.",
        suspicious: "Caution. This website looks suspicious.",
        dangerous: "Warning! Dangerous link detected. Do not open.",
        wifi: "Wi-Fi network QR code detected safely.",
        upi: "UPI payment QR detected. Please verify before paying.",
        contact: "Contact information QR code detected.",
        generic: "Scanned successfully. The code appears safe.",
        reported: "Warning! Multiple users have reported this as a scam."
    },
    ta: {
        code: "ta-IN",
        safe: "இந்த லிங்க் பாதுகாப்பானதாகத் தெரிகிறது.",
        suspicious: "எச்சரிக்கை. இந்த வலைத்தளம் சந்தேகத்திற்குரியதாக உள்ளது.",
        dangerous: "எச்சரிக்கை! ஆபத்தான லிங்க் கண்டறியப்பட்டது. திறக்க வேண்டாம்.",
        wifi: "வைஃபை QR குறியீடு பாதுகாப்பாகக் கண்டறியப்பட்டது.",
        upi: "UPI பணம் செலுத்தும் QR கண்டறியப்பட்டது. பணம் செலுத்தும் முன் சரிபார்க்கவும்.",
        contact: "தொடர்பு தகவல் QR குறியீடு கண்டறியப்பட்டது.",
        generic: "வெற்றிகரமாக ஸ்கேன் செய்யப்பட்டது. குறியீடு பாதுகாப்பானதாகத் தெரிகிறது.",
        reported: "எச்சரிக்கை! பலர் இதை மோசடி எனப் புகாரளித்துள்ளனர்."
    },
    hi: {
        code: "hi-IN",
        safe: "यह लिंक सुरक्षित लगता है।",
        suspicious: "सावधान। यह वेबसाइट संदिग्ध लगती है।",
        dangerous: "चेतावनी! खतरनाक लिंक मिला है। इसे न खोलें।",
        wifi: "वाई-फाई क्यूआर कोड सुरक्षित रूप से पहचाना गया।",
        upi: "यूपीआई भुगतान क्यूआर कोड मिला। भुगतान करने से पहले सत्यापित करें।",
        contact: "संपर्क जानकारी क्यूआर कोड मिला।",
        generic: "स्कैन सफल रहा। कोड सुरक्षित लगता है।",
        reported: "चेतावनी! कई उपयोगकर्ताओं ने इसे स्कैम बताया है।"
    }
};

function getLang() {
    return localStorage.getItem("qr_shield_lang") || "en";
}

// Google Safe Browsing API Check Function
async function checkGoogleSafeBrowsing(targetUrl) {
    const apiKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY";
    if (!apiKey || apiKey === "YOUR_GOOGLE_SAFE_BROWSING_API_KEY") {
        return false;
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
    const body = {
        client: { clientId: "qr-shield", clientVersion: "1.0.0" },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: targetUrl }]
        }
    };

    try {
        const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body)
        });
        const data = await response.json();
        if (data && data.matches && data.matches.length > 0) return true;
    } catch (error) {
        console.error("Google Safe Browsing API Error:", error);
    }
    return false;
}

// Main Security Analyzer Function
// extra: { reportCount?: number, lang?: 'en'|'ta'|'hi' }
async function analyzeURL(inputData, extra = {}) {
    if (!inputData) return 0;

    const lang = extra.lang || getLang();
    const strings = LANG_STRINGS[lang] || LANG_STRINGS.en;

    let data = inputData.trim();
    let risk = 0;
    let typeDescription = "General Text / QR Data";
    let threatMessage = "SAFE ✅";
    let circleColor = "#00ff99";
    let voiceText = strings.generic;
    let reasons = [];
    let mlProb = null;

    document.getElementById("threatDetails").innerHTML = `
        <h3>Security Details</h3>
        <p>Analyzing link safety...</p>
    `;

    if (data.startsWith("http://") || data.startsWith("https://") || data.startsWith("www.")) {
        let safeUrl = data;
        if (safeUrl.startsWith("www.")) safeUrl = "http://" + safeUrl;

        let parsedUrl;
        try {
            parsedUrl = new URL(safeUrl);
            let domain = parsedUrl.hostname;
            typeDescription = "Web URL / Link";

            let isGoogleFlagged = await checkGoogleSafeBrowsing(safeUrl);
            if (isGoogleFlagged) {
                risk = 100;
                reasons.push("Flagged by Google Safe Browsing");
            } else {
                // --- Heuristic rules (each pushes a human-readable reason) ---
                if (!data.startsWith("https://")) {
                    risk += 30;
                    reasons.push("No HTTPS encryption");
                }

                let ipPattern = /(\d{1,3}\.){3}\d{1,3}/;
                if (ipPattern.test(domain)) {
                    risk += 30;
                    reasons.push("Uses raw IP address instead of a domain name");
                }

                const keywords = ["login", "verify", "bank", "free", "gift", "bonus", "update", "paypal", "secure"];
                let hitKeywords = keywords.filter(word => data.toLowerCase().includes(word));
                if (hitKeywords.length > 0) {
                    risk += hitKeywords.length * 10;
                    reasons.push("Contains suspicious keyword(s): " + hitKeywords.join(", "));
                }

                if (data.length > 80) {
                    risk += 20;
                    reasons.push("Unusually long URL (" + data.length + " characters)");
                }

                const badDomains = [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work"];
                let hitDomain = badDomains.find(ext => domain.toLowerCase().endsWith(ext));
                if (hitDomain) {
                    risk += 30;
                    reasons.push("Domain uses a high-risk extension (" + hitDomain + ")");
                }

                // --- ML classifier (lexical logistic regression, 85.6% test accuracy) ---
                try {
                    mlProb = mlPredictPhishing(safeUrl);
                    let mlRisk = Math.round(mlProb * 100);
                    if (mlProb >= 0.5) {
                        reasons.push("ML model flags this URL as phishing-like (" + mlRisk + "% confidence)");
                    }
                    // Blend: 60% rule-based heuristics, 40% ML probability
                    risk = Math.round(risk * 0.6 + mlRisk * 0.4);
                } catch (mlErr) {
                    console.warn("ML scoring unavailable:", mlErr);
                }
            }

            // --- Community reports boost ---
            if (extra.reportCount && extra.reportCount > 0) {
                reasons.push(extra.reportCount + " user(s) reported this link as a scam");
                risk = Math.max(risk, Math.min(100, 60 + extra.reportCount * 10));
            }

            if (risk > 100) risk = 100;

            if (risk >= 70) {
                threatMessage = "DANGEROUS PHISHING 🚨";
                circleColor = "red";
                voiceText = extra.reportCount >= 3 ? strings.reported : strings.dangerous;
            } else if (risk >= 30) {
                threatMessage = "SUSPICIOUS ⚠️";
                circleColor = "orange";
                voiceText = strings.suspicious;
            } else {
                threatMessage = "SAFE ✅";
                circleColor = "#00ff99";
                voiceText = strings.safe;
                if (reasons.length === 0) reasons.push("No known risk indicators found");
            }

        } catch (e) {
            typeDescription = "Malformed URL";
            reasons.push("Could not parse this as a valid URL");
        }
    }
    else if (data.startsWith("WIFI:")) {
        typeDescription = "Wi-Fi Network QR";
        risk = 0;
        threatMessage = "SAFE ✅";
        circleColor = "#00ff99";
        voiceText = strings.wifi;
        reasons.push("Wi-Fi configuration payload, not a web link");
    }
    else if (data.startsWith("upi://")) {
        typeDescription = "UPI Payment QR (GPay / PhonePe / Paytm)";
        risk = 10;
        threatMessage = "VERIFY BENEFICIARY ⚠️";
        circleColor = "orange";
        voiceText = strings.upi;
        reasons.push("Always confirm the payee name shown by your UPI app before paying");
    }
    else if (data.startsWith("BEGIN:VCARD") || data.startsWith("tel:") || data.startsWith("mailto:")) {
        typeDescription = "Contact / Phone / Email QR";
        risk = 0;
        threatMessage = "SAFE ✅";
        circleColor = "#00ff99";
        voiceText = strings.contact;
        reasons.push("Contact-card payload, not a web link");
    } else {
        reasons.push("Unrecognized QR payload format");
    }

    // UI Updates
    document.getElementById("riskValue").innerText = risk + "%";
    document.querySelector(".circle").style.borderColor = circleColor;

    document.getElementById("result").innerText = "Scanned Data: " + data;

    let reasonsHtml = reasons.map(r => `<li>${r}</li>`).join("");
    document.getElementById("threatDetails").innerHTML = `
        <h3>Security Details</h3>
        <p><b>Data Type:</b> ${typeDescription}</p>
        <p><b>Threat Level:</b> ${threatMessage}</p>
        <p><b>Risk Score:</b> ${risk}%${mlProb !== null ? ` (ML: ${Math.round(mlProb * 100)}%)` : ""}</p>
        <p><b>Why:</b></p>
        <ul>${reasonsHtml}</ul>
    `;

    // Voice Feedback
    window.speechSynthesis.cancel();
    let voice = new SpeechSynthesisUtterance(voiceText);
    voice.lang = strings.code;
    window.speechSynthesis.speak(voice);

    return risk;
}
