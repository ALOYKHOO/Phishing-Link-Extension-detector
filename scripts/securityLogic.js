const OFFSCREEN_URL = "offscreen.html";
let creatingOffscreen = null;
 
async function ensureOffscreenDocument() {
  const offscreenUrl = chrome.runtime.getURL(OFFSCREEN_URL);
 
  const existingContexts = await chrome.runtime.getContexts({
    contextTypes: ["OFFSCREEN_DOCUMENT"],
    documentUrls: [offscreenUrl],
  });
 
  if (existingContexts.length > 0) return;
 
  if (creatingOffscreen) {
    await creatingOffscreen;
    return;
  }
 
  creatingOffscreen = chrome.offscreen.createDocument({
    url: OFFSCREEN_URL,
    reasons: ["WORKERS"],
    justification: "Run ONNX Runtime WASM inference for phishing URL detection",
  });
 
  await creatingOffscreen;
  creatingOffscreen = null;
 
  console.log("[SW] Offscreen document created");
}
 
async function runAiModel(url) {
  await ensureOffscreenDocument();
 
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      { type: "RUN_MODEL", url },
      (response) => {
        if (chrome.runtime.lastError) {
          console.error("[SW] Offscreen message error:", chrome.runtime.lastError.message);
          resolve({ confidence: 0.1, label: "unknown" });
          return;
        }
        if (!response || !response.success) {
          resolve({ confidence: 0.1, label: "unknown" });
          return;
        }
        resolve({ confidence: response.confidence, label: response.label });
      }
    );
  });
}
 
ensureOffscreenDocument().catch(console.error);
 
const tempAllowedUrls = new Set();
// --- Notification Default settings --------
 
const DEFAULT_SETTINGS = {
  safe: {
    popupBanner: true,
    showThreatLevel: true
  },
  low: {
    popupBanner: true,
    showThreatLevel: true,
    clickToProceed: true
  },
  moderate: {
    popupBanner: true,
    showThreatLevel: true,
    clickToProceed: false,
    safePage: true
  },
  high: {
    popupBanner: false,
    showThreatLevel: false,
    clickToProceed: false,
    safePage: false,
    forceReturn: true
  }
};
 
async function getNotificationSettings() {
  const data = await chrome.storage.local.get("notificationSettings");
 
  if (!data.notificationSettings) {
    await chrome.storage.local.set({ notificationSettings: DEFAULT_SETTINGS });
    return DEFAULT_SETTINGS;
  }
 
  return data.notificationSettings;
}
 
 
// ---------------- STARTUP ----------------
chrome.runtime.onInstalled.addListener(assessActiveTab);
chrome.runtime.onStartup.addListener(assessActiveTab);
 
async function assessActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return;
    await assessAndStore(tab.id, tab.url, "startup");
  } catch (err) {
    console.error("[RiskEngine] Startup assess failed:", err);
  }
}
 
 
// ---------------- TAB LISTENERS ----------------
 
const lastProcessed = new Map();
 
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab.url || lastProcessed.get(tabId) === tab.url) return;
    lastProcessed.set(tabId, tab.url);
    await assessAndStore(tabId, tab.url, "activated");
  } catch (err) {
    console.error("[RiskEngine] onActivated error:", err);
  }
});
 
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.active || !tab.url) return;
  if (lastProcessed.get(tabId) === tab.url) return;
  lastProcessed.set(tabId, tab.url);
  await assessAndStore(tabId, tab.url, "updated");
});
 
chrome.tabs.onRemoved.addListener((tabId) => {
  lastProcessed.delete(tabId);
});
 
 
// ---------------- ASSESS AND STORE ----------------
 
async function assessAndStore(tabId, url, source) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("chrome-extension://")) return;
 
  try {
    const { confidence, label } = await runAiModel(url);
    const { score: AssessResult, flags } = await calculateRiskScore(confidence, url);
 
    await chrome.storage.local.set({ risk_score: AssessResult, risk_flags: flags });
 
    await notificationTrigger(AssessResult, tabId, url);
 
    console.log(`[RiskEngine] ${source} → score: ${AssessResult}, label: ${label}, confidence: ${confidence}, flags: ${flags}`);
  } catch (err) {
    console.error("[RiskEngine] assessAndStore failed:", err);
  }
}
 
 
// ---------------- MESSAGE LISTENER ----------------
 
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ALLOW_ONCE" && message.url) {
    tempAllowedUrls.add(message.url);
    sendResponse({ success: true });
    return true;
  }
  
  if (message.type === "GET_RISK_SCORE" && message.url) {
    (async () => {
      const { confidence, label } = await runAiModel(message.url);
      const { score: AssessResult, flags } = await calculateRiskScore(confidence, message.url);
      chrome.storage.local.set({ risk_score: AssessResult, risk_flags: flags });
      sendResponse({ risk_score: AssessResult, label, flags });
    })();
    return true;
  }
});
 
 
// ---------------- HEURISTIC RULES ----------------
 
const heuristicRules = [
  {
    name: "suspiciousTLD",
    weight: 0.2,
    test: (url) => {
      const query = new URL(url).search;
      return query.length > 1 && query.length - 1 >= 50;
    }
  },
  {
    name: "susKeywords",
    weight: 0.3,
    test: (url) => {
      const keywords = ["login", "verify", "update", "secure", "add", "delete"];
      return keywords.some(k => url.toLowerCase().includes(k));
    }
  },
  {
    name: "fakeBrand",
    weight: 0.5,
    test: (url) => {
      const fakePatterns = ["paypa1", "rnicrosoft", "g00gle", "ch0tgpt", "wik1ped1A", "twi!!3r"];
      const lowerUrl = url.toLowerCase();
      return fakePatterns.some(pattern => lowerUrl.includes(pattern));
    }
  }
];

const domainRules = [

  {
    name: "suspiciousTLD",
    weight: 0.25,
    message: "⚠ Domain uses a suspicious top-level domain",

    test: (hostname) => {

      const suspiciousTLDs = [
        ".xyz",
        ".top",
        ".club",
        ".site",
        ".online",
        ".click",
        ".live"
      ];

      return suspiciousTLDs.some(
        tld => hostname.endsWith(tld)
      );
    }
  },

  {
    name: "hyphenAbuse",
    weight: 0.25,
    message: "⚠ Domain contains an unusual number of hyphens",

    test: (hostname) => {

      const hyphenCount =
        (hostname.match(/-/g) || []).length;

      return hyphenCount >= 3;
    }
  },

  {
    name: "numberHeavyDomain",
    weight: 0.25,
    message: "⚠ Domain contains an unusual number of digits",

    test: (hostname) => {

      const digitCount =
        (hostname.match(/[0-9]/g) || []).length;

      return digitCount >= 4;
    }
  },

  {
    name: "urlShortener",
    weight: 0.25,
    message: "⚠ URL uses a shortener service which may hide the real destination",

    test: (hostname) => {

      const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd"
      ];

      return shorteners.includes(hostname);
    }
  }

];
 
async function heuristicFlags(url) {
  let totalScore = 0.0;
  const triggered = [];
  for (const rule of heuristicRules) {
    if (rule.test(url)) {
      totalScore += rule.weight;
      triggered.push(rule.name);
    }
  }
  return { totalScore, triggered };
}
 
async function domainReputation(url) {
  let totalScore = 0.0;

  const triggered = [];

  try {

    const hostname =
      new URL(url)
        .hostname
        .replace(/^www\./, "")
        .toLowerCase();

    for (const rule of domainRules) {

      if (rule.test(hostname)) {

        totalScore += rule.weight;

        triggered.push(rule.name);

        console.log(
          `[DomainRule] ${rule.name} triggered`
        );
      }
    }
  } catch (err) {

    console.log(
      "[DomainRule] Failed:",
      err.message
    );
  }
  return {
    score: Number(totalScore.toFixed(2)),
    triggered
  };

}
 
async function whiteListCheck(url) {
  try {
    const checkHost = new URL(url).hostname.replace(/^www\./, "").toLowerCase();
 
    const defaultTrustedDomains = [
      "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
      "mail.google.com", "accounts.google.com", "drive.google.com",
      "docs.google.com", "meet.google.com", "maps.google.com",
      "github.com", "stackoverflow.com",
    ];
 
    if (defaultTrustedDomains.some(domain =>
      checkHost === domain || checkHost.endsWith("." + domain)
    )) {
      return true;
    }
 
    const data = await chrome.storage.local.get("urlList");
    const urlList = data.urlList || [];
 
    return urlList.some((item) => {
      try {
        const savedHost = new URL(item.url).hostname.replace(/^www\./, "").toLowerCase();
        return checkHost === savedHost || checkHost.endsWith("." + savedHost);
      } catch {
        return false;
      }
    });
 
  } catch {
    return false;
  }
}
 
async function calculateRiskScore(confidence, url) {
  const whitelisted = await whiteListCheck(url);
  if (whitelisted) return { score: 0.00, flags: [], whitelisted: true };
 
  const { score: domainScore, triggered: domainFlags } = await domainReputation(url);
  const { totalScore: heuristicScore, triggered: heuristicFlagsList } = await heuristicFlags(url);
 
  const flags = [...domainFlags, ...heuristicFlagsList];
 
  const riskScore =
    (confidence * 0.6) +
    (domainScore * 0.2) +
    (heuristicScore * 0.2);
 
  return { score: Number(riskScore.toFixed(2)), flags, whitelisted: false };
}
 
 
// ---------------- RISK LEVEL ----------------
 
function getRiskLevel(score) {
  if (score <= 0.25) return 1;
  if (score <= 0.46) return 2;
  if (score <= 0.70) return 3;
  return 4;
}
 
function getRiskKey(level) {
  return ["safe", "low", "moderate", "high"][level - 1];
}
 
 
// ---------------- NOTIFICATION TRIGGER ----------------
 
async function notificationTrigger(score, tabId, url) {

  if (tempAllowedUrls.has(url)) {
    updateBadge(getRiskLevel(score));
    return; 
  }
  
  const level = getRiskLevel(score);
  const riskKey = getRiskKey(level);
  const settings = await getNotificationSettings();
  const levelSettings = settings[riskKey] || {};
  updateBadge(level);
 
  // --- HIGH: Force return (send user back with noti pop) ---
  if (level === 4 && levelSettings.forceReturn) {
    await chrome.tabs.goBack(tabId).catch(async () => {
      await chrome.tabs.update(tabId, { url: "chrome://newtab/" });
    });
 
    // Wait briefly before injecting noti
    setTimeout(async () => {
      try {
        await chrome.tabs.sendMessage(tabId, {
          action: "SHOW_HIGH_RISK_NOTIFICATION",
          score,
          blockedUrl: url
        });
      } catch (e) {
        console.log("[RiskEngine] Could not send high risk notification:", e.message);
      }
    }, 800);
 
   
    return;
  }
 
  // --- MODERATE+: Safe page intercept ---
  if (level === 3 && levelSettings.safePage) {
    const safePageUrl =
    chrome.runtime.getURL("UI/safepage.html");

    if (url.startsWith(safePageUrl))
    return;

    chrome.tabs.update(tabId, {

    url:
      safePageUrl +
      `?score=${score}`
      + `&level=${level}`
      + `&target=${encodeURIComponent(url)}`
      + `&canProceed=true`

    });
    
    return;
  }
 
  // --- LOW+: Click-to-proceed ---
  if (level >= 2 && levelSettings.clickToProceed) {
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "PRESS_TO_PROCEED",
        riskKey
      });
    } catch (e) {
      console.log("[RiskEngine] Could not show click-to-proceed:", e.message);
    }
  }
 
  // --- ALL LEVELS: In-page banner ---
  if (levelSettings.showThreatLevel) {
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "SHOW_WARNING_DETAILS",
        level, score,
        showThreatLevel: levelSettings.showThreatLevel || false,
        riskKey
      });
    } catch (e) {
      console.log("[RiskEngine] Could not send SHOW_WARNING_DETAILS:", e.message);
    }
  }

  if (levelSettings.popupBanner) { 
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "SHOW_WARNING",
        level, score,
        showThreatLevel: levelSettings.showThreatLevel || false,
        riskKey
      });
    } catch (e) {
      console.log("[RiskEngine] Content script not ready:", e.message);
    }
  }
  
}
 
 
// ---------------- BADGE ----------------
 
function updateBadge(level) {
  if (level === 4) {
    chrome.action.setBadgeText({ text: "!!" });
    chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });
  } else if (level === 3) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#FFA500" });
  } else if (level === 2) {
    chrome.action.setBadgeText({ text: "?" });
    chrome.action.setBadgeBackgroundColor({ color: "#FFFF00" });
  } else {
    chrome.action.setBadgeText({ text: "^" });
    chrome.action.setBadgeBackgroundColor({ color: "#00db50" });
  }
}