import { saveToFirebase, reportScam, getReportCount } from './firebase.js';

let scanner = null;
let lastScannedData = null;

// ---- Language preference ----
const langSelect = document.getElementById("langSelect");
langSelect.value = localStorage.getItem("qr_shield_lang") || "en";
langSelect.onchange = () => localStorage.setItem("qr_shield_lang", langSelect.value);

// ---- Core: analyze + save + remember last scan (for report button) ----
async function runAnalysis(data) {
    lastScannedData = data;
    let reportCount = 0;
    if (data.startsWith("http://") || data.startsWith("https://") || data.startsWith("www.")) {
        try {
            reportCount = await getReportCount(data);
        } catch (e) {
            console.warn("Could not fetch community report count:", e);
        }
    }
    let riskScore = await analyzeURL(data, { reportCount, lang: langSelect.value });
    saveHistory(data, riskScore);
    return riskScore;
}

// ---- Camera scanner ----
function startScanner() {
    if (scanner) return;
    scanner = new Html5Qrcode("reader");

    scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 300, height: 300 } },
        async (qrText) => {
            await runAnalysis(qrText);
            scanner.stop().then(() => { scanner = null; }).catch(err => console.error(err));
        },
        (error) => {}
    ).catch(err => {
        console.warn("Retrying camera mode...", err);
        scanner.start(
            true,
            { fps: 10, qrbox: { width: 300, height: 300 } },
            async (qrText) => {
                await runAnalysis(qrText);
                scanner.stop().then(() => { scanner = null; });
            },
            (error) => {}
        ).catch(finalErr => {
            alert("Camera Access Error: Please check camera permissions!");
            scanner = null;
        });
    });
}

document.getElementById("scanBtn").onclick = function () {
    document.getElementById("scanner").scrollIntoView({ behavior: "smooth" });
    startScanner();
};

document.getElementById("checkUrlBtn").onclick = async function () {
    let url = document.getElementById("urlInput").value.trim();
    if (url === "") {
        alert("Please enter a URL / Text to check!");
        return;
    }
    await runAnalysis(url);
};

// ---- Batch image upload scanning ----
document.getElementById("batchInput").onchange = async function (e) {
    const files = Array.from(e.target.files);
    if (files.length === 0) return;

    const batchBox = document.getElementById("batchResults");
    batchBox.innerHTML = `<p>Scanning ${files.length} image(s)...</p>`;

    const tempScanner = new Html5Qrcode("reader");
    let resultsHtml = "";

    for (const file of files) {
        try {
            const result = await tempScanner.scanFileV2(file, false);
            const decodedText = result.decodedText;
            const risk = await runAnalysis(decodedText);
            resultsHtml += `<div class="batch-item"><b>${file.name}</b>: ${decodedText} — Risk ${risk}%</div>`;
        } catch (err) {
            resultsHtml += `<div class="batch-item error"><b>${file.name}</b>: No QR code found</div>`;
        }
    }

    batchBox.innerHTML = resultsHtml;
    e.target.value = "";
};

function saveHistory(url, risk) {
    let history = JSON.parse(localStorage.getItem("scanHistory")) || [];
    history.push({ url: url, risk: risk, date: new Date().toLocaleString() });
    localStorage.setItem("scanHistory", JSON.stringify(history));

    saveToFirebase(url, risk);
}

document.getElementById("downloadBtn").onclick = function () {
    let data = localStorage.getItem("scanHistory");
    if (!data) {
        alert("No scan history available to download!");
        return;
    }
    let file = new Blob([data], { type: "text/plain" });
    let link = document.createElement("a");
    link.href = URL.createObjectURL(file);
    link.download = "QR_Shield_Report.txt";
    link.click();
};

// ---- Community scam reporting ----
document.getElementById("reportBtn").onclick = async function () {
    if (!lastScannedData) {
        alert("Scan or check a link first, then report it.");
        return;
    }
    try {
        const result = await reportScam(lastScannedData);
        if (result.alreadyReported) {
            alert(`You already reported this. Total community reports: ${result.count}`);
        } else {
            alert(`Thanks — reported. Total community reports for this link: ${result.count}`);
            await runAnalysis(lastScannedData); // refresh risk score with the new report count
        }
    } catch (e) {
        console.error(e);
        alert("Could not submit report right now. Please try again.");
    }
};

// ---- QR Generator ----
let generatedQR = null;

document.getElementById("genBtn").onclick = function () {
    const text = document.getElementById("genInput").value.trim();
    if (!text) {
        alert("Enter some text, a link, or a UPI string to generate a QR.");
        return;
    }
    const wrap = document.getElementById("qrCanvasWrap");
    wrap.innerHTML = "";

    generatedQR = new QRCode(wrap, {
        text: text,
        width: 220,
        height: 220,
        colorDark: "#000000",
        colorLight: "#ffffff"
    });

    document.getElementById("downloadQrBtn").style.display = "inline-block";
};

document.getElementById("downloadQrBtn").onclick = function () {
    const wrap = document.getElementById("qrCanvasWrap");
    const canvas = wrap.querySelector("canvas");
    if (!canvas) {
        alert("Generate a QR code first.");
        return;
    }
    const link = document.createElement("a");
    link.download = "QR_Shield_Generated.png";
    link.href = canvas.toDataURL("image/png");
    link.click();
};
document.getElementById("downloadQrBtn").onclick = function () {
    const canvas = document.getElementById("qrCanvas");
    const link = document.createElement("a");
    link.download = "QR_Shield_Generated.png";
    link.href = canvas.toDataURL("image/png");
    link.click();
};
