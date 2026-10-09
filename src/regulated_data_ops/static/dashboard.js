"use strict";

const elements = {
  authForm: document.querySelector("#authForm"), apiKey: document.querySelector("#apiKey"),
  workspace: document.querySelector("#workspace"), notice: document.querySelector("#notice"),
  connectionDot: document.querySelector("#connectionDot"), connectionLabel: document.querySelector("#connectionLabel"),
  trustStatus: document.querySelector("#trustStatus"), trustWindow: document.querySelector("#trustWindow"),
  validRate: document.querySelector("#validRate"), quarantineRate: document.querySelector("#quarantineRate"),
  lastRun: document.querySelector("#lastRun"), lastRunMeta: document.querySelector("#lastRunMeta"),
  sourceSelect: document.querySelector("#sourceSelect"), ingestionForm: document.querySelector("#ingestionForm"),
  ingestionResult: document.querySelector("#ingestionResult"), policyVersion: document.querySelector("#policyVersion"),
  currencies: document.querySelector("#currencies"), maximumAmount: document.querySelector("#maximumAmount"),
  minimumValid: document.querySelector("#minimumValid"), policyFingerprint: document.querySelector("#policyFingerprint"),
  runsBody: document.querySelector("#runsBody"), refreshButton: document.querySelector("#refreshButton"),
  lineageForm: document.querySelector("#lineageForm"), eventId: document.querySelector("#eventId"),
  lineageResult: document.querySelector("#lineageResult"), actorLabel: document.querySelector("#actorLabel")
};

let apiKey = sessionStorage.getItem("regulatedDataApiKey") || "";
let permissions = new Set();

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("X-API-Key", apiKey);
  if (options.body) headers.set("Content-Type", "application/json");
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { const body = await response.json(); message = body.detail || message; } catch (_) { /* generic status */ }
    throw new Error(message);
  }
  return response.json();
}

function text(element, value) { element.textContent = value == null ? "—" : String(value); }
function percent(value) { return `${(Number(value || 0) * 100).toFixed(1)}%`; }
function shortHash(value) { return value ? `${String(value).slice(0, 12)}…` : "—"; }
function clear(element) { while (element.firstChild) element.removeChild(element.firstChild); }

function setConnected(connected, identity = null) {
  elements.workspace.classList.toggle("is-locked", !connected);
  elements.connectionDot.classList.toggle("online", connected);
  text(elements.connectionLabel, connected ? "Sesión autenticada" : "Sin autenticar");
  text(elements.actorLabel, identity ? `${identity.display_name} · ${identity.role}` : "Identidad no verificada");
}

function showNotice(message, isError = false) {
  text(elements.notice, message);
  elements.notice.classList.add("visible");
  elements.notice.classList.toggle("error", isError);
}

function hideNotice() { elements.notice.classList.remove("visible", "error"); }

async function loadDashboard() {
  const identity = await request("/api/v1/me");
  permissions = new Set(identity.permissions || []);
  const [status, report] = await Promise.all([
    request("/api/v1/status"), request("/api/v1/trust-report?limit=10")
  ]);
  const sources = permissions.has("sources:read") ? await request("/api/v1/sources") : { sources: [] };
  const policy = permissions.has("policy:read") ? await request("/api/v1/policy") : null;
  renderStatus(status, report); renderRuns(report.runs || []); renderSources(sources.sources || []); renderPolicy(policy);
  elements.ingestionForm.querySelector("button").disabled = !permissions.has("ingestion:create");
  elements.lineageForm.querySelector("button").disabled = !permissions.has("lineage:read");
  setConnected(true, identity); hideNotice();
}

function renderStatus(status, report) {
  text(elements.trustStatus, report.overall_status || "no_data");
  text(elements.trustWindow, `${report.window_runs || 0} ejecuciones evaluadas`);
  text(elements.validRate, percent(report.valid_rate)); text(elements.quarantineRate, percent(report.quarantine_rate));
  const run = status.latest_run;
  text(elements.lastRun, run ? (run.status || "—") : "sin datos");
  text(elements.lastRunMeta, run ? `${run.source_name || "fuente"} · ${run.duration_ms || 0} ms` : "No disponible");
}

function renderRuns(runs) {
  clear(elements.runsBody);
  if (!runs.length) { const row = elements.runsBody.insertRow(); const cell = row.insertCell(); cell.colSpan = 5; text(cell, "Sin ejecuciones registradas"); return; }
  runs.forEach(run => {
    const row = elements.runsBody.insertRow();
    [run.source_name || "—", run.contract_version || "—", run.total_rows ?? "—", `${run.duration_ms || 0} ms`].forEach(value => text(row.insertCell(), value));
    const cell = row.insertCell(); const pill = document.createElement("span"); pill.className = `status-pill ${run.trust_status === "breached" ? "breached" : ""}`; text(pill, run.trust_status || "—"); cell.appendChild(pill);
  });
}

function renderSources(sources) {
  clear(elements.sourceSelect);
  if (!sources.length) { const option = document.createElement("option"); option.value = ""; text(option, "No hay CSV disponibles"); elements.sourceSelect.appendChild(option); return; }
  sources.forEach(source => { const option = document.createElement("option"); option.value = source.name; text(option, `${source.name} · ${source.size_bytes} B`); elements.sourceSelect.appendChild(option); });
}

function renderPolicy(policy) {
  if (!policy) {
    text(elements.policyVersion, "Restringida"); text(elements.currencies, "Requiere policy:read");
    text(elements.maximumAmount, "—"); text(elements.minimumValid, "—"); text(elements.policyFingerprint, "—");
    return;
  }
  text(elements.policyVersion, policy.policy_version); text(elements.currencies, policy.rules.allowed_currencies.join(" · "));
  text(elements.maximumAmount, policy.rules.maximum_amount); text(elements.minimumValid, percent(policy.slo.minimum_valid_rate));
  text(elements.policyFingerprint, shortHash(policy.fingerprint)); elements.policyFingerprint.title = policy.fingerprint;
}

function renderDefinitionList(element, data) {
  clear(element);
  Object.entries(data).forEach(([key, value]) => { const wrap = document.createElement("div"); const term = document.createElement("dt"); const detail = document.createElement("dd"); text(term, key.replaceAll("_", " ")); text(detail, value); wrap.append(term, detail); element.appendChild(wrap); });
}

elements.authForm.addEventListener("submit", async event => {
  event.preventDefault(); apiKey = elements.apiKey.value.trim();
  try { await loadDashboard(); sessionStorage.setItem("regulatedDataApiKey", apiKey); elements.apiKey.value = ""; }
  catch (error) { apiKey = ""; sessionStorage.removeItem("regulatedDataApiKey"); setConnected(false); showNotice(`No fue posible autenticar: ${error.message}`, true); }
});

elements.ingestionForm.addEventListener("submit", async event => {
  event.preventDefault(); elements.ingestionResult.className = "result-box"; text(elements.ingestionResult, "Ejecutando control contractual…");
  if (!permissions.has("ingestion:create")) { elements.ingestionResult.classList.add("error"); text(elements.ingestionResult, "El rol actual no puede ejecutar ingestas."); return; }
  try { const result = await request("/api/v1/ingestions", { method: "POST", body: JSON.stringify({ source: elements.sourceSelect.value }) }); elements.ingestionResult.classList.add("success"); text(elements.ingestionResult, `${result.source_name}: ${result.trust_status} · ${result.accepted_rows} aceptadas · ${result.quarantined_rows} en cuarentena`); await loadDashboard().catch(error => showNotice(`La ingesta terminó, pero no fue posible actualizar: ${error.message}`, true)); }
  catch (error) { elements.ingestionResult.classList.add("error"); text(elements.ingestionResult, `Operación rechazada: ${error.message}`); }
});

elements.lineageForm.addEventListener("submit", async event => {
  event.preventDefault();
  if (!permissions.has("lineage:read")) { renderDefinitionList(elements.lineageResult, { estado: "El rol actual no puede consultar lineage" }); return; }
  try { const result = await request(`/api/v1/lineage/${encodeURIComponent(elements.eventId.value.trim())}`); renderDefinitionList(elements.lineageResult, result); }
  catch (error) { renderDefinitionList(elements.lineageResult, { estado: `No disponible: ${error.message}` }); }
});

elements.refreshButton.addEventListener("click", () => loadDashboard().catch(error => showNotice(error.message, true)));

if (apiKey) loadDashboard().catch(() => { apiKey = ""; sessionStorage.removeItem("regulatedDataApiKey"); setConnected(false); });
