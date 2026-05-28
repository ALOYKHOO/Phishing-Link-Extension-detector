chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "SHOW_WARNING") {
    showWarningBanner(message.level, message.score, message.riskKey);
  }
});

function showWarningBanner(level, score, riskKey) {
  if (!level) return;

  const existing = document.getElementById("phishing-warning");
  if (existing) return;

   const banner = document.createElement("div");
  banner.id = "phishing-warning";

  // Position
  banner.style.position = "fixed";
  banner.style.top = "20px";
  banner.style.right = "10px";   
  banner.style.width = "260px";  
  banner.style.padding = "12px 16px";
  banner.style.zIndex = "999999";

  // Style
  banner.style.fontSize = "14px"; 
  banner.style.fontWeight = "600";
  banner.style.color = "white";
  banner.style.borderRadius = "12px"; 
  banner.style.boxShadow = "0 4px 12px rgba(0,0,0,0.3)";
  banner.style.display = "flex";
  banner.style.justifyContent = "space-between";
  banner.style.alignItems = "center";
  banner.style.opacity = "1";
  banner.style.transition = "opacity 0.5s ease, transform 0.3s ease";
  banner.style.transform = "translateY(-10px)";

  // Color logic
  if (level === 4) banner.style.backgroundColor = "#e53935"; 
  else if (level === 3) banner.style.backgroundColor = "#fb8c00";
  else if (level === 2) {
    banner.style.backgroundColor = "#fdd835";
    banner.style.color = "black";
  } else banner.style.backgroundColor = "#43a047";

  const text = document.createElement("span");
  text.innerText = `⚠ Risk Level ${level}: ${riskKey} (${(score * 100).toFixed(0)}%)`;

  const closeBtn = document.createElement("span");
  closeBtn.innerText = "✖";
  closeBtn.style.cursor = "pointer";
  closeBtn.style.marginLeft = "10px";
  closeBtn.style.fontSize = "14px";
  closeBtn.onclick = () => banner.remove();

  banner.appendChild(text);
  banner.appendChild(closeBtn);

  if (document.body) {
    document.body.appendChild(banner);
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      document.body.appendChild(banner);
    });
  }

  // Animate in
  setTimeout(() => {
    banner.style.transform = "translateY(0)";
  }, 50);

  // Auto-dismiss
  setTimeout(() => {
    banner.style.opacity = "0";
    banner.style.transform = "translateY(-10px)";
    setTimeout(() => banner.remove(), 500);
  }, 2000);
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "PRESS_TO_PROCEED") {
    showPopupClick(message.riskKey);
  }
});

function showPopupClick(riskKey){
    alert("Detected " + riskKey + " risk link, proceed?");
}



chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SHOW_HIGH_RISK_NOTIFICATION") {
    createHighRiskToast(request.blockedUrl, request.score);
  }
});

function createHighRiskToast(url, score) {
  // Prevent duplicate notifications
  if (document.getElementById("risk-engine-alert")) return;

  const toast = document.createElement("div");
  toast.id = "risk-engine-alert";
  
  // Style the toast
  Object.assign(toast.style, {
    position: "fixed",
    top: "20px",
    right: "20px",
    backgroundColor: "#b91c1c", // Dark red
    color: "white",
    padding: "16px",
    borderRadius: "8px",
    zIndex: "999999",
    boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
    maxWidth: "350px",
    fontFamily: "sans-serif",
    borderLeft: "5px solid #7f1d1d"
  });

  toast.innerHTML = `
    <div style="font-weight: bold; margin-bottom: 5px; display: flex; align-items: center;">
      <span style="margin-right: 8px;">⚠️</span> Access Blocked
    </div>
    <div style="font-size: 13px; opacity: 0.9;">
      The site <strong>${new URL(url).hostname}</strong> was blocked due to a high risk score (${score}).
    </div>
    <button id="close-risk-toast" style="margin-top: 10px; background: transparent; border: 1px solid white; color: white; cursor: pointer; padding: 2px 8px; border-radius: 4px; font-size: 11px;">Dismiss</button>
  `;

  document.body.appendChild(toast);

  document.getElementById("close-risk-toast").onclick = () => toast.remove();

  // Auto-remove after 8 seconds
  setTimeout(() => toast.remove(), 8000);
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SHOW_WARNING_DETAILS") {
    renderPhishBanner(request);
  }
});

function renderPhishBanner(data) {
  const existing = document.getElementById("phish-banner-container");
  if (existing) existing.remove();

  const banner = document.createElement("div");
  banner.id = "phish-banner-container";
  
  const colors = ["#22c55e", "#eab308", "#f97316", "#ef4444"];
  const activeColor = colors[data.level - 1];
  const riskLabels = ["Safe", "Low Risk", "Moderate Risk", "High Risk"];

  Object.assign(banner.style, {
    position: "fixed",
    top: "15px",
    right: "15px",
    width: "320px",
    backgroundColor: "#18153B", // Match .card
    borderRadius: "12px",
    zIndex: "2147483647",
    boxShadow: "0 10px 30px rgba(0,0,0,0.6)",
    fontFamily: "Arial, sans-serif",
    color: "#C9D3FF",
    border: `1px solid ${activeColor}`,
    transition: "opacity 1s ease-out", 
    opacity: "1",
    overflow: "hidden"
  });

  banner.innerHTML = `
    <div style="background-color: #5B6A83; padding: 10px; display: flex; align-items: center; gap: 10px;">
      <div style="line-height: 1.1;">
        <div style="font-weight: bold; font-size: 14px;">Phishappear</div>
        <div style="font-size: 10px; opacity: 0.7;">Powered By BERT Transformer AI</div>
      </div>
      <button id="close-p-banner" style="margin-left: auto; background: none; border: none; color: white; cursor: pointer; font-size: 20px;">&times;</button>
    </div>

    <div style="padding: 15px;">
      <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-bottom: 15px;">
        ${[1, 2, 3, 4].map(i => `
          <div style="height: 8px; border-radius: 10px; background: ${i <= data.level ? activeColor : "#2a2a2a"};"></div>
        `).join("")}
      </div>

      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
        <div style="width: 0; height: 0; border-left: 10px solid transparent; border-right: 10px solid transparent; border-bottom: 25px solid ${activeColor};"></div>
        <div style="font-weight: bold; font-size: 16px;">${riskLabels[data.level - 1]}</div>
        <div style="margin-left: auto; font-weight: bold;">${(data.score * 100).toFixed(0)}%</div>
      </div>
    </div>
  `;

  document.body.appendChild(banner);
  const fadeOutTimer = setTimeout(() => {
    banner.style.opacity = "0";
    setTimeout(() => banner.remove(), 1000);
  }, 5000);

  // Clear timer if user clicks "X" manually so it doesn't try to remove twice
  document.getElementById("close-p-banner").onclick = () => {
    clearTimeout(fadeOutTimer);
    banner.remove();
  };
}