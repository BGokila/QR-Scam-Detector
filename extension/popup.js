// Lightweight standalone analyzer for the extension popup
// (same heuristics + ML model as the main site, without the DOM/Firebase dependencies)
function analyzeLite(data) {
    let risk = 0;
    let reasons = [];

    if (data.startsWith("http://") || data.startsWith("https://") || data.startsWith("www.")) {
        let safeUrl = data.startsWith("www.") ? "http://" + data : data;
        try {
            let domain = new URL(safeUrl).hostname;

            if (!data.startsWith("https://")) { risk += 30; reasons.push("No HTTPS encryption"); }

            if (/(\d{1,3}\.){3}\d{1,3}/.test(domain)) { risk += 30; reasons.push("Raw IP address domain"); }

            const keywords = ["login", "verify", "bank", "free", "gift", "bonus", "update", "paypal", "secure"];
            let hits = keywords.filter(w => data.toLowerCase().includes(w));
            if (hits.length) { risk += hits.length * 10; reasons.push("Suspicious keyword(s): " + hits.join(", ")); }

            if (data.length > 80) { risk += 20; reasons.push("Unusually long URL"); }

            const badDomains = [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".work"];
            let bad = badDomains.find(ext => domain.toLowerCase().endsWith(ext));
            if (bad) { risk += 30; reasons.push("High-risk domain extension (" + bad + ")"); }

            let mlProb = mlPredictPhishing(safeUrl);
            let mlRisk = Math.round(mlProb * 100);
            if (mlProb >= 0.5) reasons.push("ML model flags as phishing-like (" + mlRisk + "%)");
            risk = Math.round(risk * 0.6 + mlRisk * 0.4);

            if (risk > 100) risk = 100;
            if (reasons.length === 0) reasons.push("No known risk indicators found");
            return { risk, reasons, type: "Web URL" };
        } catch (e) {
            return { risk: 0, reasons: ["Could not parse as a URL"], type: "Malformed" };
        }
    } else if (data.startsWith("upi://")) {
        return { risk: 10, reasons: ["Always verify the payee name before paying"], type: "UPI Payment" };
    } else if (data.startsWith("WIFI:")) {
        return { risk: 0, reasons: ["Wi-Fi configuration payload"], type: "Wi-Fi" };
    } else {
        return { risk: 0, reasons: ["Not a link — general text"], type: "Text" };
    }
}

function render(data, analysis) {
    const box = document.getElementById("result");
    const level = analysis.risk >= 70 ? "DANGEROUS 🚨" : analysis.risk >= 30 ? "SUSPICIOUS ⚠️" : "SAFE ✅";
    const color = analysis.risk >= 70 ? "#ff4d4d" : analysis.risk >= 30 ? "orange" : "#00ff99";
    box.innerHTML = `
        <p style="color:${color}; font-weight:bold;">${level} — Risk ${analysis.risk}%</p>
        <p><b>Type:</b> ${analysis.type}</p>
        <ul>${analysis.reasons.map(r => `<li>${r}</li>`).join("")}</ul>
    `;
}

// Check current active tab on open
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0]?.url || "";
    document.getElementById("pageUrl").innerText = url;
    render(url, analyzeLite(url));
});

document.getElementById("checkBtn").onclick = () => {
    const val = document.getElementById("manualInput").value.trim();
    if (!val) return;
    render(val, analyzeLite(val));
};
