import { saveToFirebase } from './firebase.js';

let scanner = null;

function startScanner() {
    if (scanner) return;

    scanner = new Html5Qrcode("reader");

    scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 300, height: 300 } },
        async (qrText) => {
            let riskScore = await analyzeURL(qrText);
            saveHistory(qrText, riskScore);

            scanner.stop().then(() => { scanner = null; }).catch(err => console.error(err));
        },
        (error) => {}
    ).catch(err => {
        console.warn("Retrying camera mode...", err);
        scanner.start(
            true, 
            { fps: 10, qrbox: { width: 300, height: 300 } },
            async (qrText) => {
                let riskScore = await analyzeURL(qrText);
                saveHistory(qrText, riskScore);
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

    let riskScore = await analyzeURL(url);
    saveHistory(url, riskScore);
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