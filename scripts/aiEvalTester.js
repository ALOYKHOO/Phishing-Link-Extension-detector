let ortSession = null;
let char2idx = {};
const MAX_LEN = 120;
 
// ─── MODEL INIT ───────────────────────────────────────────────────────────────
async function initModel() {
    const status = document.getElementById("loadingStatus");
    status.textContent = "Loading model files...";
 
    try {
        const vocabRes = await fetch(chrome.runtime.getURL("model/char2idx.json"));
        char2idx = await vocabRes.json();
 
        const modelUrl = chrome.runtime.getURL("model/transformer_model.onnx");
        const dataUrl  = chrome.runtime.getURL("model/transformer_model.onnx.data");
 
        const [modelBuffer, dataBuffer] = await Promise.all([
            fetch(modelUrl).then(r => r.arrayBuffer()),
            fetch(dataUrl).then(r => r.arrayBuffer())
        ]);
 
        ortSession = await ort.InferenceSession.create(modelBuffer, {
            executionProviders: ["wasm"],
            externalData: [{
                path: "transformer_model.onnx.data",
                data: new Uint8Array(dataBuffer)
            }]
        });
 
        status.textContent = "Model ready.";
    } catch (err) {
        console.error("Initialization failed:", err);
        status.textContent = "Error loading model. Check console.";
    }
}
 
// ─── RISK LEVEL ───────────────────────────────────────────────────────────────
function getRiskLevel(score) {
    if (score <= 0.25) return "1 (Safe)";
    if (score <= 0.46) return "2 (Low)";
    if (score <= 0.70) return "3 (Moderate)";
    return "4 (High)";
}
 
function getRiskLabel(score) {
    if (score <= 0.25) return "safe";
    if (score <= 0.46) return "low";
    if (score <= 0.70) return "moderate";
    return "high";
}
 
// ─── ONNX INFERENCE ───────────────────────────────────────────────────────────
async function analyzeUrl(url) {
    if (!ortSession) return null;
 
    const cleanUrl = url.toLowerCase().replace(/^https?:\/\//, "");
    const padded = new Array(MAX_LEN).fill(0);
    Array.from(cleanUrl).slice(0, MAX_LEN).forEach((c, i) => {
        padded[i] = char2idx[c] || 0;
    });
 
    const inputTensor = new ort.Tensor("int64", BigInt64Array.from(padded.map(BigInt)), [1, MAX_LEN]);
    const results = await ortSession.run({ input: inputTensor });
 
    const logit = Number(results["output"].data[0]);
    const score  = 1 / (1 + Math.exp(-logit));
 
    return { score, level: getRiskLevel(score), label: getRiskLabel(score) };
}
 
// ─── CLIENT-SIDE URL EXPLAINER ────────────────────────────────────────────────
function explainUrl(rawUrl, score, riskLabel) {
    let url;
    try { url = new URL(rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl); }
    catch { url = { hostname: rawUrl, pathname: "/", href: rawUrl, search: "" }; }
 
    const hostname = url.hostname.toLowerCase();
    const pathname = url.pathname.toLowerCase();
    const href     = url.href.toLowerCase();
    const search   = url.search.toLowerCase();
 
    const indicators = [];
 
    // 1. IP address instead of domain
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        indicators.push({
            label: "IP Address Used as Domain",
            detail: "Legitimate sites use domain names, not raw IP addresses. This is a strong phishing signal.",
            severity: "high"
        });
    }
 
    // 2. Suspicious TLD
    const suspiciousTLDs = [".xyz",".top",".click",".gq",".ml",".cf",".tk",".pw",".work",".loan",".date",".win",".bid",".stream",".download"];
    const matchedTLD = suspiciousTLDs.find(t => hostname.endsWith(t));
    if (matchedTLD) {
        indicators.push({
            label: "Suspicious Top-Level Domain",
            detail: 'The "' + matchedTLD + '" TLD is frequently abused by phishing campaigns due to its low cost or free registration.',
            severity: "high"
        });
    }
 
    // 3. Brand impersonation
    const brands = ["paypal","apple","google","microsoft","amazon","netflix","facebook","instagram","whatsapp","bank","ebay","steam","discord","dropbox","linkedin"];
    const domainRoot = hostname.replace(/^www\./, "").split(".")[0];
    const brandHit = brands.find(b => hostname.includes(b) && domainRoot !== b);
    if (brandHit) {
        indicators.push({
            label: "Brand Name Impersonation",
            detail: 'URL contains "' + brandHit + '" but the actual domain is different — a classic spoofing tactic to deceive users.',
            severity: "high"
        });
    }
 
    // 4. Excessive subdomains
    const subdomainCount = hostname.split(".").length - 2;
    if (subdomainCount >= 3) {
        indicators.push({
            label: "Excessive Subdomains",
            detail: subdomainCount + " subdomain levels detected. Attackers stack subdomains to make the real domain harder to spot.",
            severity: "medium"
        });
    } else if (subdomainCount === 2) {
        indicators.push({
            label: "Multiple Subdomains",
            detail: "More than one subdomain is present, which can obscure the actual domain owner.",
            severity: "low"
        });
    }
 
    // 5. Hyphens in domain
    const hyphenCount = (hostname.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
        indicators.push({
            label: "Excessive Hyphens in Domain",
            detail: hyphenCount + " hyphens found. Phishing domains often chain hyphens (e.g. secure-login-verify-paypal.com) to mimic real sites.",
            severity: "high"
        });
    } else if (hyphenCount >= 1) {
        indicators.push({
            label: "Hyphens in Domain Name",
            detail: hyphenCount + " hyphen(s) in the domain. While sometimes legitimate, this pattern is common in spoofed domains.",
            severity: "low"
        });
    }
 
    // 6. Long URL
    if (href.length > 100) {
        indicators.push({
            label: "Unusually Long URL",
            detail: "URL is " + href.length + " characters. Long URLs hide the real destination or bury suspicious path segments.",
            severity: "medium"
        });
    }
 
    // 7. URL shortener
    const shorteners = ["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly","is.gd","rebrand.ly","short.io","cutt.ly"];
    if (shorteners.some(s => hostname.includes(s))) {
        indicators.push({
            label: "URL Shortener Detected",
            detail: "Shortened URLs mask the real destination and are commonly used to bypass link-based phishing filters.",
            severity: "medium"
        });
    }
 
    // 8. @ symbol
    if (href.includes("@")) {
        indicators.push({
            label: "@ Symbol in URL",
            detail: "The '@' character forces browsers to ignore everything before it, silently redirecting to a hidden domain.",
            severity: "high"
        });
    }
 
    // 9. Percent-encoded characters
    const encodedCount = (href.match(/%[0-9a-f]{2}/gi) || []).length;
    if (encodedCount >= 4) {
        indicators.push({
            label: "Heavy URL Encoding",
            detail: encodedCount + " encoded sequences found. Attackers encode characters to hide malicious keywords from URL scanners.",
            severity: "high"
        });
    } else if (encodedCount >= 1) {
        indicators.push({
            label: "URL Encoding Present",
            detail: encodedCount + " encoded character(s) found. This can disguise suspicious words in the URL.",
            severity: "low"
        });
    }
 
    // 10. Phishing keywords in path/query
    const badKeywords = ["login","signin","verify","secure","account","update","confirm","password","credential","banking","suspend","unlock","billing","checkout","auth"];
    const foundKeywords = badKeywords.filter(k => pathname.includes(k) || search.includes(k));
    if (foundKeywords.length >= 2) {
        indicators.push({
            label: "Multiple Phishing Keywords",
            detail: "Path/query contains: " + foundKeywords.slice(0, 4).join(", ") + ". Stacking these words is a hallmark of credential-harvesting pages.",
            severity: "high"
        });
    } else if (foundKeywords.length === 1) {
        indicators.push({
            label: "Phishing Keyword in URL",
            detail: 'Found "' + foundKeywords[0] + '" in the URL. This keyword is commonly associated with fake login or credential-phishing pages.',
            severity: "medium"
        });
    }
 
    // 11. No HTTPS
    if (rawUrl.startsWith("http://")) {
        indicators.push({
            label: "No HTTPS Encryption",
            detail: "The connection is unencrypted. Passwords and personal data submitted on this page can be intercepted.",
            severity: "medium"
        });
    }
 
    // 12. Executable file extension
    if (/\.(exe|zip|rar|bat|cmd|msi|apk|scr|dmg|php)\b/.test(pathname)) {
        indicators.push({
            label: "Executable File Extension in Path",
            detail: "The URL points to an executable or archive file, which may indicate a drive-by download or malware distribution.",
            severity: "high"
        });
    }
 
    // 13. Safe signals
    if ((riskLabel === "safe" || riskLabel === "low") && indicators.length === 0) {
        const knownTLDs = [".com",".org",".edu",".gov",".net",".io",".co.uk",".com.my",".de",".fr",".jp"];
        if (knownTLDs.some(t => hostname.endsWith(t))) {
            indicators.push({
                label: "Reputable Domain Extension",
                detail: "The TLD is well-established and associated with lower phishing rates.",
                severity: "safe"
            });
        }
        if (!hostname.includes("-") && hostname.split(".").length <= 3) {
            indicators.push({
                label: "Clean Domain Structure",
                detail: "No excessive subdomains or hyphens — the domain structure matches patterns of legitimate websites.",
                severity: "safe"
            });
        }
        if (foundKeywords.length === 0) {
            indicators.push({
                label: "No Suspicious Keywords",
                detail: "The URL path contains no credential-harvesting or login-manipulation keywords.",
                severity: "safe"
            });
        }
    }
 
    // Fallback
    if (indicators.length === 0) {
        indicators.push({
            label: "AI Pattern Detection",
            detail: "The model detected phishing patterns in the character-level structure of this URL that are not visible as simple rules.",
            severity: riskLabel === "high" ? "high" : "medium"
        });
    }
 
    // Summary & recommendation
    const scorePercent = (score * 100).toFixed(1);
    var summary, recommendation;
 
    if (riskLabel === "safe") {
        summary = "This URL scored " + scorePercent + "% risk and appears to be safe based on its structure and domain characteristics.";
        recommendation = "This link appears safe to visit. Always stay cautious when submitting personal information online.";
    } else if (riskLabel === "low") {
        summary = "This URL scored " + scorePercent + "% risk. It shows minor suspicious signals but may still be legitimate.";
        recommendation = "Proceed with caution. Verify the domain carefully before entering any credentials.";
    } else if (riskLabel === "moderate") {
        summary = "This URL scored " + scorePercent + "% risk. Several phishing indicators were detected in its structure.";
        recommendation = "Avoid submitting personal data on this page. Verify the site's legitimacy through official channels.";
    } else {
        summary = "This URL scored " + scorePercent + "% risk. Strong phishing signals were detected — this link is likely malicious.";
        recommendation = "Do NOT visit or interact with this link. Close the page immediately and report it if received via message or email.";
    }
 
    return { summary, indicators: indicators.slice(0, 5), recommendation };
}
 
// ─── SEVERITY HELPERS — no emoji, use CSS badges instead ─────────────────────
function severityColor(s) {
    return { high: "#ff4d6d", medium: "#ffb347", low: "#ffd166", safe: "#4ade80" }[s] || "#c3c3dc";
}
 
function severityBadge(s) {
    var labels = { high: "HIGH", medium: "MED", low: "LOW", safe: "SAFE" };
    var colors = { high: "#ff4d6d", medium: "#ffb347", low: "#ffd166", safe: "#4ade80" };
    var label = labels[s] || s.toUpperCase();
    var color = colors[s] || "#c3c3dc";
    return '<span style="' +
        'display:inline-block;' +
        'font-size:9px;' +
        'font-weight:700;' +
        'letter-spacing:0.8px;' +
        'padding:2px 6px;' +
        'border-radius:4px;' +
        'border:1px solid ' + color + ';' +
        'color:' + color + ';' +
        'flex-shrink:0;' +
        'margin-top:2px;' +
    '">' + label + '</span>';
}
 
// ─── RENDER ───────────────────────────────────────────────────────────────────
function renderExplanation(explanation) {
    var container = document.getElementById("explanationContainer");
    if (!container || !explanation) return;
 
    var indicatorsHTML = explanation.indicators.map(function(ind) {
        return '<div style="' +
            'display:flex; align-items:flex-start; gap:10px;' +
            'padding:10px 12px; border-radius:6px;' +
            'background:rgba(255,255,255,0.04);' +
            'margin-bottom:8px;' +
            'border-left:3px solid ' + severityColor(ind.severity) + ';' +
        '">' +
            severityBadge(ind.severity) +
            '<div>' +
                '<div style="font-weight:600; color:' + severityColor(ind.severity) + '; font-size:13px; margin-bottom:3px;">' + ind.label + '</div>' +
                '<div style="color:#c3c3dc; font-size:12px; line-height:1.5;">' + ind.detail + '</div>' +
            '</div>' +
        '</div>';
    }).join("");
 
    container.innerHTML =
        '<div style="display:flex; align-items:center; gap:8px; margin-bottom:14px; padding-bottom:10px; border-bottom:1px solid rgba(195,195,220,0.12);">' +
            '<span style="font-size:14px; font-weight:700; color:#e0e0f0; letter-spacing:0.3px;">Detailed Analysis</span>' +
        '</div>' +
 
        '<p style="color:#e0e0f0; font-size:13px; margin:0 0 14px 0; line-height:1.6;">' + explanation.summary + '</p>' +
 
        '<div style="font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#8888aa; margin-bottom:8px;">Risk Indicators</div>' +
 
        indicatorsHTML +
 
        '<div style="margin-top:14px; padding:10px 14px; background:rgba(100,160,255,0.07); border:1px solid rgba(100,160,255,0.18); border-radius:6px;">' +
            '<div style="font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#8888aa; margin-bottom:4px;">Recommendation</div>' +
            '<div style="color:#c3c3dc; font-size:13px; line-height:1.5;">' + explanation.recommendation + '</div>' +
        '</div>';
 
    container.style.display = "block";
}
 
// ─── BUTTON HANDLER ───────────────────────────────────────────────────────────
document.getElementById("runTest").addEventListener("click", async function() {
    var url = document.getElementById("testUrl").value.trim();
    if (!url) return;
 
    var resultDiv      = document.getElementById("testResult");
    var scoreSpan      = document.getElementById("resScore");
    var levelSpan      = document.getElementById("resLevel");
    var explanationDiv = document.getElementById("explanationContainer");
    var status         = document.getElementById("loadingStatus");
 
    explanationDiv.innerHTML = "";
    explanationDiv.style.display = "none";
    resultDiv.style.display = "none";
    status.textContent = "Analyzing URL...";
 
    var result = await analyzeUrl(url);
    if (!result) {
        status.textContent = "Model not ready. Please wait and try again.";
        return;
    }
 
    scoreSpan.textContent = result.score.toFixed(4);
    levelSpan.textContent = result.level;
    resultDiv.style.display = "block";
 
    var explanation = explainUrl(url, result.score, result.label);
    renderExplanation(explanation);
 
    status.textContent = "";
});
 
initModel();