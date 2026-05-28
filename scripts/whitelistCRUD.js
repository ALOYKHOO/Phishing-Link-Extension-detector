const showBtn = document.getElementById("addURL");
const dialog = document.getElementById("addSiteDialog");
const form = document.getElementById("addForm");
const removeBtn = document.getElementById("removeURL");
const confirmDeleteBtn = document.getElementById("confirmDelete");
const tableBody = document.querySelector("#listURL tbody");
 
//dialog
showBtn.addEventListener("click", () => {
  dialog.showModal(); 
});
 
// Load list
function renderList(urlList) {
  tableBody.innerHTML = ""; // clear before re-rendering
 
  if (urlList.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.textContent = "No URLs in whitelist.";
    td.style.textAlign = "center";
    tr.appendChild(td);
    tableBody.appendChild(tr);
    return;
  }
 
  urlList.forEach((item, index) => {
    const tr = document.createElement("tr");
    tr.dataset.index = index; // store index
 
    // Name cell
    const nameTd = document.createElement("td");
    nameTd.textContent = item.name;
 
    // URL cell
    const urlTd = document.createElement("td");
    urlTd.innerHTML = `<a href="${item.url}" target="_blank">${item.url}</a>`;
 
    // Date cell
    const dateTd = document.createElement("td");
    dateTd.textContent = item.date || "N/A";
 
    tr.appendChild(nameTd);
    tr.appendChild(urlTd);
    tr.appendChild(dateTd);
 
    tableBody.appendChild(tr);
  });
}
 
async function loadList() {
  const data = await chrome.storage.local.get("urlList");
  const entries = data.urlList || [];
  renderList(entries);
  return entries;
}
 
// Add new entry
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const data = await chrome.storage.local.get("urlList");
  const urlList = data.urlList || [];
 
  const now = new Date();
  const newEntry = {
    name: document.getElementById("webname").value.trim(),
    url: document.getElementById("whitelistURL").value.trim(),
    date: now.toLocaleDateString() + " " + now.toLocaleTimeString()
  };
 
  urlList.push(newEntry);
  await chrome.storage.local.set({ urlList });
 
  renderList(urlList);
  form.reset();
  dialog.close();
});
 
//cancel
document.querySelector(".btn.no").addEventListener("click", () => {
  dialog.close();
  form.reset();
});
 
loadList();
 
 
//Remove URL
 
let removeMode = false;
let selectedIndices = new Set();
 
function exitRemoveMode() {
  removeMode = false;
  selectedIndices.clear();
  removeBtn.textContent = "Remove URL";
  tableBody.style.cursor = "default";
  confirmDeleteBtn.style.display = "none";
  clearSelection();
}
 
// Toggle remove mode on/off
removeBtn.addEventListener("click", () => {
  removeMode = !removeMode;
 
  if (removeMode) {
    removeBtn.textContent = "Cancel";
    tableBody.style.cursor = "pointer";
    confirmDeleteBtn.style.display = "inline-block";
  } else {
    exitRemoveMode();
  }
});
 
// Click a row to highlights red
tableBody.addEventListener("click", (e) => {
  if (!removeMode) return;
 
  const row = e.target.closest("tr");
  if (!row || row.dataset.index === undefined) return;
 
  const idx = row.dataset.index;
 
  if (selectedIndices.has(idx)) {
    selectedIndices.delete(idx);
    row.classList.remove("selected");
  } else {
    selectedIndices.add(idx);
    row.classList.add("selected");
  }
});
 
// Confirm Delete button
confirmDeleteBtn.addEventListener("click", async () => {
  if (selectedIndices.size === 0) {
    alert("No URLs selected. Click on rows to select them first.");
    return;
  }
 
  const selectedRows = [...document.querySelectorAll("tr.selected")];
  const names = selectedRows.map(r => `• ${r.cells[0].textContent}`).join("\n");
  const confirmed = confirm(`Remove the following ${selectedIndices.size} URL(s) from whitelist?\n\n${names}`);
  if (!confirmed) return;
 
  const data = await chrome.storage.local.get("urlList");
  let urlList = data.urlList || [];
 
  const sortedIndices = [...selectedIndices].map(Number).sort((a, b) => b - a);
  sortedIndices.forEach(i => urlList.splice(i, 1));
 
  await chrome.storage.local.set({ urlList });
  renderList(urlList);
  exitRemoveMode();
});
 
function clearSelection() {
  document.querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected"));
}
 