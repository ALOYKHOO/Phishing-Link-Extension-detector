const MAX_LEN = 120;
 
let ortSession = null;
let char2idx = {};
 

ort.env.wasm.wasmPaths = chrome.runtime.getURL("lib/");
 
async function loadModel() {
  if (ortSession) return ortSession;
 
  // Load vocab
  const vocabRes = await fetch(chrome.runtime.getURL("model/char2idx.json"));
  char2idx = await vocabRes.json();
 

  const modelUrl = chrome.runtime.getURL("model/transformer_model.onnx");
  const dataUrl  = chrome.runtime.getURL("model/transformer_model.onnx.data");
 
  console.log("[Offscreen] Fetching model files...");
 
  const [modelBuffer, dataBuffer] = await Promise.all([
    fetch(modelUrl).then(r => r.arrayBuffer()),
    fetch(dataUrl).then(r  => r.arrayBuffer()),
  ]);
 
  console.log(
    `[Offscreen] model: ${modelBuffer.byteLength} bytes, ` +
    `data: ${dataBuffer.byteLength} bytes`
  );
 
  ortSession = await ort.InferenceSession.create(
    modelBuffer,
    {
      executionProviders: ["wasm"],
      graphOptimizationLevel: "all",
      externalData: [
        {
          path: "transformer_model.onnx.data",
          data: dataBuffer,
        }
      ],
    }
  );
 
  console.log("[Offscreen] Model loaded successfully");
  return ortSession;
}
 
async function runInference(url) {
  const session = await loadModel();
 
  // Strip protocol to match training preprocessing
  const cleanUrl = url.toLowerCase().replace(/^https?:\/\//, "");
 
  const padded = new Array(MAX_LEN).fill(0);
  Array.from(cleanUrl).slice(0, MAX_LEN).forEach((c, i) => {
    padded[i] = char2idx[c] || 0;
  });
 
  const inputTensor = new ort.Tensor(
    "int64",
    BigInt64Array.from(padded.map(BigInt)),
    [1, MAX_LEN]
  );
 
  // Use "input" to match your ONNX export's input_names=['input']
  const results = await session.run({ input: inputTensor });
 
  const logit      = Number(results["output"].data[0]);
  const confidence = 1 / (1 + Math.exp(-logit));
  const label      = confidence > 0.5 ? "phishing" : "legitimate";
 
  console.log(`[Offscreen] label: ${label}, confidence: ${confidence.toFixed(4)}`);
  return { confidence, label };
}
 
// Listen for RUN_MODEL messages from the service worker
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== "RUN_MODEL") return false;
 
  runInference(message.url)
    .then(result => sendResponse({ success: true, ...result }))
    .catch(err  => {
      console.error("[Offscreen] Inference failed:", err);
      sendResponse({ success: false, confidence: 0.6, label: "unknown" });
    });
 
  return true; 
});
 
// Pre-warm model on page load
loadModel()
  .then(() => console.log("[Offscreen] Model pre-warmed and ready"))
  .catch(e  => console.error("[Offscreen] Pre-warm failed:", e));