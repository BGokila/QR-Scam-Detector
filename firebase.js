import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getDatabase, ref, push, onValue, remove, get, set, runTransaction } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js";

const firebaseConfig = {
    apiKey: "AIzaSyAueOOAN_sBCp052ED40rQuNX0EP5_WU6c",
    authDomain: "qr-scanner-9337c.firebaseapp.com",
    projectId: "qr-scanner-9337c",
    storageBucket: "qr-scanner-9337c.firebasestorage.app",
    messagingSenderId: "119416356994",
    appId: "1:119416356994:web:f4352a669ac6955ff7349b",
    measurementId: "G-0J230GSZYE"
};

const app = initializeApp(firebaseConfig);
const database = getDatabase(app);


function getDeviceId() {
    let deviceId = localStorage.getItem("qr_shield_device_id");
    if (!deviceId) {
        deviceId = "user_" + Math.random().toString(36).substr(2, 9) + "_" + Date.now();
        localStorage.setItem("qr_shield_device_id", deviceId);
    }
    return deviceId;
}

// Firebase Realtime Database keys can't contain . # $ [ ] / — sanitize a URL into a safe key
function urlToKey(url) {
    return encodeURIComponent(url).replace(/[.#$\[\]/]/g, "_").slice(0, 200);
}


export function saveToFirebase(url, riskScore) {
    const deviceId = getDeviceId();
    const scanRef = ref(database, `scans/${deviceId}`);
    push(scanRef, {
        url: url,
        risk: riskScore,
        date: new Date().toLocaleString()
    }).then(() => {
        console.log("Successfully saved to Firebase Realtime Database!");
    }).catch((err) => {
        console.error("Firebase Save Error: ", err);
    });
}


export function loadFirebaseHistory(callback) {
    const deviceId = getDeviceId();
    const scanRef = ref(database, `scans/${deviceId}`);
    onValue(scanRef, (snapshot) => {
        const data = snapshot.val();
        callback(data);
    });
}


export function clearFirebaseHistory() {
    const deviceId = getDeviceId();
    const scanRef = ref(database, `scans/${deviceId}`);
    remove(scanRef);
}

// ---- Community Scam Reporting ----

// One report per device per URL (a device can't inflate the same URL's count twice)
export async function reportScam(url) {
    const deviceId = getDeviceId();
    const key = urlToKey(url);
    const voterRef = ref(database, `reports/${key}/voters/${deviceId}`);

    const voterSnap = await get(voterRef);
    if (voterSnap.exists()) {
        const countSnap = await get(ref(database, `reports/${key}/count`));
        return { alreadyReported: true, count: countSnap.val() || 0 };
    }

    await set(voterRef, true);
    await set(ref(database, `reports/${key}/url`), url);

    const countRef = ref(database, `reports/${key}/count`);
    const result = await runTransaction(countRef, (current) => (current || 0) + 1);
    return { alreadyReported: false, count: result.snapshot.val() || 0 };
}

// Returns how many users have reported this exact URL as a scam
export async function getReportCount(url) {
    const key = urlToKey(url);
    const snap = await get(ref(database, `reports/${key}/count`));
    return snap.val() || 0;
}
