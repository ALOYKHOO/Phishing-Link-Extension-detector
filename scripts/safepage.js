// ---------------- GET TARGET URL ----------------
const params = new URLSearchParams(location.search);
const targetUrl = params.get("target");


const urlDisplay = document.getElementById("url");
if (urlDisplay && targetUrl) {
  try {
    urlDisplay.textContent = decodeURIComponent(targetUrl);
  } catch {
    urlDisplay.textContent = targetUrl;
  }
}

// ---------------- YES BUTTON (PROCEED) ----------------
const proceedBtn = document.getElementById("proceedBtn");
const cancelBtn = document.getElementById("cancelBtn");

proceedBtn?.addEventListener("click", () => {
  if (!targetUrl) {
    location.href = "https://www.google.com";
    return;
  }

  const decoded = decodeURIComponent(targetUrl);

  chrome.runtime.sendMessage(
    { type: "ALLOW_ONCE", url: decoded },
    () => {
      
      setTimeout(() => {
        location.href = decoded;
      }, 50);
    }
  );
});


cancelBtn?.addEventListener("click", () => {
    location.href = "https://www.google.com";
});
