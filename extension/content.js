console.log("🛡️ Guardrail Injected (v3 - Robust Capture)");

const API_URL = "http://127.0.0.1:5000/scan";
let typingTimer; 

// 1. VISUAL: Create the "System Active" Badge
const badge = document.createElement("div");
badge.id = "trust-badge";
badge.innerText = "🛡️ Trust System Active";
document.body.appendChild(badge);

function updateBadge(color, text) {
    badge.style.backgroundColor = color;
    badge.innerText = text;
    setTimeout(() => {
        badge.style.backgroundColor = "#2563eb"; 
        badge.innerText = "🛡️ Trust System Active";
    }, 3000);
}

// 2. HELPER: Get clean text from ChatGPT or Gemini
function getInputText() {
    // Strategy 1: Try ChatGPT's specific ID
    const chatGPTInput = document.querySelector('#prompt-textarea');
    if (chatGPTInput) return chatGPTInput.innerText;

    // Strategy 2: Get whatever is currently focused (Universal)
    const active = document.activeElement;
    if (active && (active.isContentEditable || active.tagName === 'TEXTAREA')) {
        return active.innerText || active.value || "";
    }
    
    return "";
}

// 3. LOGIC: Send data to Backend
async function sendToBackend(text, localPiiDetected = false) {
    console.log("📤 Sending to Backend:", text, "PII Flag:", localPiiDetected); 
    updateBadge("#d97706", "⏳ Scanning..."); 
    
    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                text: text, 
                source_url: window.location.href,
                local_pii_detected: localPiiDetected // Explicitly tell backend we found PII
            })
        });
        const data = await response.json();
        
        if (data.pii_detected) {
            console.log("⚠️ Backend confirmed PII");
            updateBadge("#dc2626", "⚠️ PII Detected!");
        } else {
            console.log("✅ Backend said Safe");
            updateBadge("#16a34a", "✅ Verified Safe");
        }
    } catch (err) {
        console.error("❌ Network Error:", err);
        updateBadge("#dc2626", "❌ Connection Error");
    }
}

// 4. TRIGGER: Input Listener (Global)
document.addEventListener('input', (e) => {
    // Robust Capture: Get text from the active element
    const text = getInputText();
    const active = document.activeElement;

    // VISUAL LOCAL CHECK (Immediate Feedback)
    const isEmail = text.includes("@") && text.includes(".");
    const isPhone = /\b\d{10}\b/.test(text); // Checks for 10 consecutive digits
    const isPii = isEmail || isPhone;

    if (isEmail) {
        if (active) active.style.border = "2px solid red";
        updateBadge("#dc2626", "🚫 PII Warning: Email");
    } else if (isPhone) {
        if (active) active.style.border = "2px solid red";
        updateBadge("#dc2626", "🚫 PII Warning: Phone");
    } else {
        // Reset border if PII is removed
        if (active) active.style.border = "none";
    }

    // BACKEND SYNC (Debounced)
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => {
        if (text.trim().length > 3) {
            // Pass the local PII verdict to the backend
            sendToBackend(text, isPii);
        }
    }, 1000); // Wait 1s after you stop typing
});

// 5. TRIGGER: Output Scanner (AI Responses)
const observer = new MutationObserver((mutations) => {
    const messages = document.querySelectorAll('p, .markdown'); 
    messages.forEach(msg => {
        msg.onclick = function() {
            // Output scanning is usually server-side, so we pass false for local detection
            sendToBackend(msg.innerText, false);
            msg.style.borderLeft = "4px solid blue"; 
        };
    });
});
observer.observe(document.body, { childList: true, subtree: true });