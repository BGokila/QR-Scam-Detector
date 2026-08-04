import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import { getDatabase, ref, push, onValue, remove } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-database.js";

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