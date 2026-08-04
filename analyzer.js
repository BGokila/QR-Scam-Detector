// function analyzeURL(inputData) {
//     if (!inputData) return 0;

//     let data = inputData.trim();
//     let risk = 0;
//     let typeDescription = "General Text / QR Data";
//     let threatMessage = "SAFE ✅";
//     let circleColor = "#00ff99";
//     let voiceText = "Scanned successfully. The code appears safe.";

//     // 1. Check if it's a Web URL (http / https / www)
//     if (data.startsWith("http://") || data.startsWith("https://") || data.startsWith("www.")) {
//         let safeUrl = data;
//         if (safeUrl.startsWith("www.")) safeUrl = "http://" + safeUrl;

//         let parsedUrl;
//         try {
//             parsedUrl = new URL(safeUrl);
//             let domain = parsedUrl.hostname;
//             typeDescription = "Web URL / Link";

//             // Security Threat Logic for URLs
//             if (!data.startsWith("https://")) risk += 30;

//             let ipPattern = /(\d{1,3}\.){3}\d{1,3}/;
//             if (ipPattern.test(domain)) risk += 30;

//             const keywords = ["login", "verify", "bank", "free", "gift", "bonus", "update", "paypal", "secure"];
//             keywords.forEach(word => {
//                 if (data.toLowerCase().includes(word)) risk += 10;
//             });

//             if (data.length > 80) risk += 20;

//             const badDomains = [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work"];
//             badDomains.forEach(ext => {
//                 if (domain.toLowerCase().endsWith(ext)) risk += 30;
//             });

//             if (risk > 100) risk = 100;

//             if (risk >= 70) {
//                 threatMessage = "DANGEROUS PHISHING 🚨";
//                 circleColor = "red";
//                 voiceText = "Warning! Dangerous link detected. Do not open.";
//             } else if (risk >= 30) {
//                 threatMessage = "SUSPICIOUS ⚠️";
//                 circleColor = "orange";
//                 voiceText = "Caution. This website looks suspicious.";
//             } else {
//                 threatMessage = "SAFE ✅";
//                 circleColor = "#00ff99";
//                 voiceText = "The link appears safe to visit.";
//             }

//         } catch (e) {
//             typeDescription = "Malformed URL";
//         }
//     } 
//     // 2. Check if it's Wi-Fi QR
//     else if (data.startsWith("WIFI:")) {
//         typeDescription = "Wi-Fi Network QR";
//         risk = 0;
//         threatMessage = "SAFE ✅";
//         circleColor = "#00ff99";
//         voiceText = "Wi-Fi network QR code detected safely.";
//     } 
//     // 3. Check if it's UPI Payment QR (GPay, PhonePe, Paytm etc.)
//     else if (data.startsWith("upi://")) {
//         typeDescription = "UPI Payment QR (GPay / PhonePe / Paytm)";
//         risk = 10; 
//         threatMessage = "VERIFY BENEFICIARY ⚠️";
//         circleColor = "orange";
//         voiceText = "UPI payment QR detected. Please verify before paying.";
//     } 
//     // 4. Check if it's Contact (vCard / Phone / Email)
//     else if (data.startsWith("BEGIN:VCARD") || data.startsWith("tel:") || data.startsWith("mailto:")) {
//         typeDescription = "Contact / Phone / Email QR";
//         risk = 0;
//         threatMessage = "SAFE ✅";
//         circleColor = "#00ff99";
//         voiceText = "Contact information QR code detected.";
//     }

//     // UI Updates
//     document.getElementById("riskValue").innerText = risk + "%";
//     document.querySelector(".circle").style.borderColor = circleColor;
    
//     document.getElementById("result").innerText = "Scanned Data: " + data;
//     document.getElementById("threatDetails").innerHTML = `
//         <h3>Security Details</h3>
//         <p><b>Data Type:</b> ${typeDescription}</p>
//         <p><b>Threat Level:</b> ${threatMessage}</p>
//         <p><b>Risk Score:</b> ${risk}%</p>
//     `;

//     // Voice Feedback
//     window.speechSynthesis.cancel();
//     let voice = new SpeechSynthesisUtterance(voiceText);
//     window.speechSynthesis.speak(voice);

//     return risk;
// }




// Google Safe Browsing API Check Function
async function checkGoogleSafeBrowsing(targetUrl) {
    
    const apiKey = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"; 
    
    // API Key போடப்படவில்லை என்றால் API செக்-ஐத் தவிர்த்து பழைய லோஜிக்கிற்குச் செல்லும்
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

        if (data && data.matches && data.matches.length > 0) {
            return true; // Google API Flagged as Dangerous
        }
    } catch (error) {
        console.error("Google Safe Browsing API Error:", error);
    }
    return false;
}

// Main Security Analyzer Function
async function analyzeURL(inputData) {
    if (!inputData) return 0;

    let data = inputData.trim();
    let risk = 0;
    let typeDescription = "General Text / QR Data";
    let threatMessage = "SAFE ✅";
    let circleColor = "#00ff99";
    let voiceText = "Scanned successfully. The code appears safe.";

    // UI Checking State
    document.getElementById("threatDetails").innerHTML = `
        <h3>Security Details</h3>
        <p>Analyzing link safety...</p>
    `;

    // 1. Check if it's a Web URL
    if (data.startsWith("http://") || data.startsWith("https://") || data.startsWith("www.")) {
        let safeUrl = data;
        if (safeUrl.startsWith("www.")) safeUrl = "http://" + safeUrl;

        let parsedUrl;
        try {
            parsedUrl = new URL(safeUrl);
            let domain = parsedUrl.hostname;
            typeDescription = "Web URL / Link";

            // --- Step A: Google Safe Browsing Check ---
            let isGoogleFlagged = await checkGoogleSafeBrowsing(safeUrl);
            if (isGoogleFlagged) {
                risk = 100;
            } else {
                // --- Step B: Heuristic Security Rules ---
                if (!data.startsWith("https://")) risk += 30;

                let ipPattern = /(\d{1,3}\.){3}\d{1,3}/;
                if (ipPattern.test(domain)) risk += 30;

                const keywords = ["login", "verify", "bank", "free", "gift", "bonus", "update", "paypal", "secure"];
                keywords.forEach(word => {
                    if (data.toLowerCase().includes(word)) risk += 10;
                });

                if (data.length > 80) risk += 20;

                const badDomains = [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work"];
                badDomains.forEach(ext => {
                    if (domain.toLowerCase().endsWith(ext)) risk += 30;
                });
            }

            if (risk > 100) risk = 100;

            if (risk >= 70) {
                threatMessage = "DANGEROUS PHISHING 🚨";
                circleColor = "red";
                voiceText = "Warning! Dangerous link detected. Do not open.";
            } else if (risk >= 30) {
                threatMessage = "SUSPICIOUS ⚠️";
                circleColor = "orange";
                voiceText = "Caution. This website looks suspicious.";
            } else {
                threatMessage = "SAFE ✅";
                circleColor = "#00ff99";
                voiceText = "The link appears safe to visit.";
            }

        } catch (e) {
            typeDescription = "Malformed URL";
        }
    } 
    // 2. Wi-Fi QR
    else if (data.startsWith("WIFI:")) {
        typeDescription = "Wi-Fi Network QR";
        risk = 0;
        threatMessage = "SAFE ✅";
        circleColor = "#00ff99";
        voiceText = "Wi-Fi network QR code detected safely.";
    } 
    // 3. UPI Payment QR
    else if (data.startsWith("upi://")) {
        typeDescription = "UPI Payment QR (GPay / PhonePe / Paytm)";
        risk = 10; 
        threatMessage = "VERIFY BENEFICIARY ⚠️";
        circleColor = "orange";
        voiceText = "UPI payment QR detected. Please verify before paying.";
    } 
    // 4. Contact QR
    else if (data.startsWith("BEGIN:VCARD") || data.startsWith("tel:") || data.startsWith("mailto:")) {
        typeDescription = "Contact / Phone / Email QR";
        risk = 0;
        threatMessage = "SAFE ✅";
        circleColor = "#00ff99";
        voiceText = "Contact information QR code detected.";
    }

    // UI Updates
    document.getElementById("riskValue").innerText = risk + "%";
    document.querySelector(".circle").style.borderColor = circleColor;
    
    document.getElementById("result").innerText = "Scanned Data: " + data;
    document.getElementById("threatDetails").innerHTML = `
        <h3>Security Details</h3>
        <p><b>Data Type:</b> ${typeDescription}</p>
        <p><b>Threat Level:</b> ${threatMessage}</p>
        <p><b>Risk Score:</b> ${risk}%</p>
    `;

    // Voice Feedback
    window.speechSynthesis.cancel();
    let voice = new SpeechSynthesisUtterance(voiceText);
    window.speechSynthesis.speak(voice);

    return risk;
}