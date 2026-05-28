document.addEventListener("DOMContentLoaded", () => {
  initWarningPrefPage();
});
 
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
    clickToProceed: true,
    safePage: true
  },
  high: {
    popupBanner: false,
    showThreatLevel: true,
    clickToProceed: true,
    safePage: true,
    forceReturn: true
  }
};
 
 
// ---------------- INITIALIZATION ----------------
 
function initWarningPrefPage() {
  loadSettings();
  enableAutoSave();
}
 
 
// ---------------- LOAD SETTINGS ----------------
 
async function loadSettings() {
  const data = await chrome.storage.local.get("notificationSettings");
 
  
  if (!data.notificationSettings) {
    await chrome.storage.local.set({ notificationSettings: DEFAULT_SETTINGS });
  }
 
  const settings = data.notificationSettings || DEFAULT_SETTINGS;
  applySettingsToCheckboxes(settings);
}
 
 
// ---------------- APPLY TO CHECKBOXES ----------------
 
function applySettingsToCheckboxes(settings) {
 
  document.getElementById("safe-popupBanner").checked =
    settings.safe.popupBanner;
  document.getElementById("safe-showThreatLevel").checked =
    settings.safe.showThreatLevel;
 
  document.getElementById("low_popup").checked =
    settings.low.popupBanner;
  document.getElementById("low_show_level").checked =
    settings.low.showThreatLevel;
  document.getElementById("low_safe_page").checked =
    settings.low.clickToProceed;
 
  document.getElementById("mod_popup").checked =
    settings.moderate.popupBanner;
  document.getElementById("mod_show_level").checked =
    settings.moderate.showThreatLevel;
  document.getElementById("mod_force").checked =
    settings.moderate.clickToProceed;
  document.getElementById("mod_safe_page").checked =
    settings.moderate.safePage;
 
  document.getElementById("high_popup").checked =
    settings.high.popupBanner;
  document.getElementById("high_show_level").checked =
    settings.high.showThreatLevel;
  document.getElementById("high_force").checked =
    settings.high.clickToProceed;
  document.getElementById("high_safe_page").checked =
    settings.high.safePage;
  document.getElementById("high_return").checked =
    settings.high.forceReturn;
}
 
 
// ---------------- AUTO SAVE ----------------
 
function enableAutoSave() {
  const checkboxes = document.querySelectorAll("input[type='checkbox']");
  checkboxes.forEach(cb => {
    cb.addEventListener("change", saveSettings);
  });
}
 
 
// ---------------- SAVE SETTINGS ----------------
 
async function saveSettings() {
  const settings = {
    safe: {
      popupBanner:
        document.getElementById("safe-popupBanner").checked,
      showThreatLevel:
        document.getElementById("safe-showThreatLevel").checked
    },
    low: {
      popupBanner:
        document.getElementById("low_popup").checked,
      showThreatLevel:
        document.getElementById("low_show_level").checked,
      clickToProceed:
        document.getElementById("low_safe_page").checked
    },
    moderate: {
      popupBanner:
        document.getElementById("mod_popup").checked,
      showThreatLevel:
        document.getElementById("mod_show_level").checked,
      clickToProceed:
        document.getElementById("mod_force").checked,
      safePage:
        document.getElementById("mod_safe_page").checked
    },
    high: {
      popupBanner:
        document.getElementById("high_popup").checked,
      showThreatLevel:
        document.getElementById("high_show_level").checked,
      clickToProceed:
        document.getElementById("high_force").checked,
      safePage:
        document.getElementById("high_safe_page").checked,
      forceReturn:
        document.getElementById("high_return").checked
    }
  };
 
  await chrome.storage.local.set({ notificationSettings: settings });
  console.log("Notification settings saved:", settings);
}