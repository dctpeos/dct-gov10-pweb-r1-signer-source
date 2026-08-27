import {
  CLASSIFICATION,
  PROFILE_ID,
  PROFILE_VERSION,
  SYNTHETIC_DECISION_DIGEST,
  recoverAndSignSyntheticTestOnly,
  runtimeCapabilitySelfTest,
} from "./signer_core.mjs";

// Filled deterministically after the reviewed cryptographic core files are
// finalized. This identifies the core, not the outer ZIP or live page bytes.
export const APPROVED_CORE_IDENTITY_SHA256 = "1d20039c50611b3147173dbd993bef5f85fda7755d14010fef61b6681b9391a9";

const byId = (id) => document.getElementById(id);
const capability = byId("capability");
const status = byId("status");
const mnemonic = byId("mnemonic");
const output = byId("output");
const executeButton = byId("execute");
const clearButton = byId("clear");
const airplane = byId("airplane-confirmed");

byId("profile-id").textContent = PROFILE_ID;
byId("profile-version").textContent = PROFILE_VERSION;
byId("classification").textContent = CLASSIFICATION;
byId("core-identity").textContent = APPROVED_CORE_IDENTITY_SHA256;
byId("decision-digest").value = SYNTHETIC_DECISION_DIGEST;

function setStatus(message, kind = "neutral") {
  status.textContent = message;
  status.dataset.kind = kind;
}

export function clearSensitiveState() {
  mnemonic.value = "";
  output.value = "";
  airplane.checked = false;
  executeButton.disabled = true;
  setStatus("CLEARED — close this page and remove Safari website data before reconnecting.");
}

let runtimePass = false;
try {
  const result = await runtimeCapabilitySelfTest();
  runtimePass = result.status === "PASS_RUNTIME_CAPABILITY_SYNTHETIC_ONLY";
  capability.textContent = runtimePass
    ? "PASS — WebCrypto Ed25519/PBKDF2/HMAC/digest known-answer checks"
    : "FAIL — unsupported runtime";
  capability.dataset.kind = runtimePass ? "pass" : "fail";
} catch (error) {
  capability.textContent = `FAIL — ${error.code || error.name || "RUNTIME_CAPABILITY_FAILURE"}`;
  capability.dataset.kind = "fail";
}

function updateAvailability() {
  executeButton.disabled = !(runtimePass && airplane.checked && mnemonic.value.length > 0);
}

airplane.addEventListener("change", updateAvailability);
mnemonic.addEventListener("input", updateAvailability);
mnemonic.addEventListener("copy", (event) => event.preventDefault());
mnemonic.addEventListener("cut", (event) => event.preventDefault());
mnemonic.addEventListener("paste", (event) => event.preventDefault());
mnemonic.addEventListener("drop", (event) => event.preventDefault());
mnemonic.addEventListener("dragstart", (event) => event.preventDefault());

executeButton.addEventListener("click", async () => {
  output.value = "";
  if (!runtimePass) {
    setStatus("FAIL_CLOSED_RUNTIME_CAPABILITY_NOT_VERIFIED", "fail");
    return;
  }
  if (!airplane.checked) {
    setStatus("FAIL_CLOSED_AIRPLANE_MODE_OWNER_CONFIRMATION_REQUIRED", "fail");
    return;
  }
  executeButton.disabled = true;
  setStatus("Working in volatile memory…");
  const phrase = mnemonic.value;
  try {
    const result = await recoverAndSignSyntheticTestOnly({
      copyLabel: byId("copy-label").value,
      mnemonic: phrase,
      decisionDigest: SYNTHETIC_DECISION_DIGEST,
    });
    output.value = JSON.stringify(result, null, 2);
    setStatus(result.status, "pass");
  } catch (error) {
    setStatus(`FAIL_CLOSED_${error.code || error.name || "QUALIFICATION_FAILURE"}`, "fail");
  } finally {
    mnemonic.value = "";
    executeButton.disabled = true;
  }
});

clearButton.addEventListener("click", clearSensitiveState);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) clearSensitiveState();
});
window.addEventListener("pagehide", clearSensitiveState);
