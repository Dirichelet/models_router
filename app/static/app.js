const state = { csrfToken: null, models: [], providerModels: [], selectedProviderModels: new Set(), providerModelsLoading: false, chatHistory: [], keywordRules: [] };

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#039;", '"': "&quot;" })[char]);

function setMessage(message, kind = "error") {
  const target = $("#app-message");
  target.textContent = message;
  target.className = `app-message ${kind === "success" ? "success" : ""}`;
}

function showView(name) {
  document.querySelectorAll(".app-view").forEach((view) => { view.hidden = view.dataset.view !== name; });
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.viewTarget === name));
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("Content-Type", "application/json");
  if (["POST", "PUT", "PATCH", "DELETE"].includes(options.method) && state.csrfToken) headers.set("X-CSRF-Token", state.csrfToken);
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) showAuth();
    throw new Error(data.detail || "请求失败");
  }
  return data;
}

function showAuth() {
  $("#app-shell").hidden = true;
  $("#auth-panel").hidden = false;
  state.csrfToken = null;
  state.chatHistory = [];
}

function showApp(user) {
  $("#auth-panel").hidden = true;
  $("#app-shell").hidden = false;
  $("#current-user").textContent = user.username;
  showView("chat");
}

function percentage(part, total) { return total ? `${Math.round((part / total) * 100)}%` : "—"; }

function renderEvaluation(evaluation) {
  const successful = evaluation.successful_chat_calls || 0;
  const compliantRoutes = Math.max(0, successful - (evaluation.routing_fallbacks || 0));
  $("#signal-privacy").textContent = evaluation.privacy_blocks || 0;
  $("#signal-privacy-note").textContent = `${evaluation.privacy_blocks || 0} / ${evaluation.chat_calls || 0} 聊天调用被安全阻断`;
  $("#signal-routing").textContent = percentage(compliantRoutes, successful);
  $("#signal-routing-note").textContent = `${evaluation.routing_fallbacks || 0} 次使用最低价回退`;
  $("#signal-cost").textContent = percentage(evaluation.known_cost_chat_calls || 0, successful);
  $("#signal-cost-note").textContent = `${evaluation.known_cost_chat_calls || 0} / ${successful} 成功调用可核验`;
}

function renderPipelineStatus(pipeline) {
  const pill = $("#pipeline-status");
  const submit = $("#chat-submit");
  if (pipeline.local_runtime_error) {
    pill.textContent = pipeline.local_runtime_error;
    pill.classList.add("warning");
    submit.disabled = true;
    return;
  }
  if (pipeline.invalid_required_credentials?.length) {
    pill.textContent = `需重填 API Key：${pipeline.invalid_required_credentials.join("、")}`;
    pill.classList.add("warning");
    submit.disabled = true;
    return;
  }
  if (pipeline.ready) {
    const skipped = pipeline.invalid_targets?.length || 0;
    const targetLabel = `${pipeline.available_targets ?? pipeline.active_targets} 个目标`;
    const redactorLabel = pipeline.redactor || "不脱敏";
    const routerLabel = pipeline.router || "默认难度/费率路由";
    pill.textContent = skipped
      ? `已就绪：${redactorLabel} → ${routerLabel} → ${targetLabel}（已跳过 ${skipped} 个需重填 Key 的目标）`
      : `已就绪：${redactorLabel} → ${routerLabel} → ${targetLabel}`;
    pill.classList.toggle("warning", Boolean(skipped));
    submit.disabled = false;
  } else {
    const missing = [!pipeline.available_targets && "可用目标模型"].filter(Boolean).join("、");
    pill.textContent = pipeline.invalid_targets?.length
      ? `需重填至少一个目标模型 API Key：${pipeline.invalid_targets.join("、")}`
      : `缺少：${missing}`;
    pill.classList.add("warning");
    submit.disabled = true;
  }
}

function renderServiceApi(keyStatus) {
  const baseUrl = `${window.location.origin}/v1`;
  $("#service-api-base-url").textContent = baseUrl;
  $("#service-api-example").textContent = [
    `curl ${baseUrl}/chat/completions \\`,
    "  -H 'Authorization: Bearer <YOUR_MODELS_ROUTER_KEY>' \\",
    "  -H 'Content-Type: application/json' \\",
    "  -d '{\"model\":\"models-router\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}'",
  ].join("\n");
  $("#service-key-status").textContent = keyStatus.active
    ? `服务 API Key 已启用：${keyStatus.prefix}（创建于 ${new Date(keyStatus.created_at).toLocaleString()}）`
    : "尚未生成服务 API Key。外部 Agent 和 Chat 客户端无法调用服务。";
  $("#revoke-service-key").disabled = !keyStatus.active;
}

async function loadDashboard() {
  const [models, rules, calls, stats, evaluation, pipeline, serviceKey, keywordRules] = await Promise.all([
    api("/api/models"), api("/api/rules"), api("/api/calls"), api("/api/stats"), api("/api/evaluation"), api("/api/pipeline/status"), api("/api/service-key"), api("/api/keyword-rules"),
  ]);
  state.models = models;
  state.keywordRules = keywordRules;
  renderModels();
  renderCalls(calls);
  $("#redaction-rule").value = rules.redaction || "";
  $("#routing-rule").value = rules.routing || "";
  $("#metric-calls").textContent = stats.total_calls || 0;
  $("#metric-success").textContent = stats.successful_calls || 0;
  $("#metric-cost").textContent = `$${Number(stats.total_cost || 0).toFixed(6)}`;
  $("#metric-cost-note").textContent = stats.unknown_cost_calls ? `${stats.unknown_cost_calls} 条调用未返回完整 usage` : "";
  renderEvaluation(evaluation);
  renderPipelineStatus(pipeline);
  renderServiceApi(serviceKey);
  renderKeywordRules();
}

function renderModels() {
  const container = $("#models-list");
  if (!state.models.length) {
    container.innerHTML = '<div class="empty-state">尚未配置模型。API Key 仅以加密形式保存在服务器。</div>';
    return;
  }
  const roleLabel = (role) => ({ redactor: "旧 Provider 脱敏（不会调用）", router: "路由模型", target: "目标模型" })[role] || role;
  container.innerHTML = state.models.map((model) => `
    <div class="model-row"><div><h3>${escapeHtml(model.name)} <span class="role-tag ${escapeHtml(model.role)}">${roleLabel(model.role)}</span> ${model.is_active ? "" : "<span class=\"muted\">(已停用)</span>"} ${model.credential_ready ? "" : "<span class=\"credential-warning\">API Key 需重填</span>"}</h3>
    <p>${escapeHtml(model.role)} · ${escapeHtml(model.model_name)} · $${Number(model.input_price_per_million).toFixed(4)}/$${Number(model.output_price_per_million).toFixed(4)} 每百万 token</p></div>
    <div class="model-actions">${model.role === "redactor" ? "" : `<button class="ghost test-model" data-id="${model.id}" type="button">测试</button><button class="ghost edit-model" data-id="${model.id}" type="button">编辑</button>`}<button class="ghost danger delete-model" data-id="${model.id}" type="button">删除</button></div></div>`).join("");
}

function renderCalls(calls) {
  const table = $("#calls-table");
  if (!calls.length) { table.innerHTML = '<tr><td colspan="6" class="muted">暂无调用记录</td></tr>'; return; }
  table.innerHTML = calls.map((call) => `
    <tr><td>${escapeHtml(new Date(call.created_at).toLocaleString())}</td><td>${call.kind === "connection_test" ? "连接测试" : "聊天"}</td><td>${escapeHtml(call.selected_model_name || call.redactor_model_name || call.router_model_name || "—")}</td>
    <td title="${escapeHtml(call.redacted_message || call.error_message || "")}">${escapeHtml((call.redacted_message || call.error_message || "—").slice(0, 180))}</td>
    <td>${call.cost_known ? `$${Number(call.total_cost || 0).toFixed(6)}` : "待 Provider 确认"}<br><span class="muted">${call.prompt_tokens + call.completion_tokens} tokens</span></td>
    <td class="status-${escapeHtml(call.status)}">${escapeHtml(call.status)}</td></tr>`).join("");
}

function renderKeywordRules() {
  const container = $("#keyword-rules-list");
  if (!state.keywordRules.length) { container.innerHTML = '<div class="empty-state">尚未配置关键词规则。</div>'; return; }
  container.innerHTML = state.keywordRules.map((rule) => `
    <div class="keyword-rule ${rule.is_active ? "" : "inactive"}"><div><strong>${escapeHtml(rule.phrase)}</strong> <span class="muted">→</span> <code>${escapeHtml(rule.replacement)}</code><div class="muted">${rule.is_fuzzy ? "模糊匹配" : "精确匹配"} · ${rule.is_active ? "已启用" : "已停用"}</div></div>
    <div class="model-actions"><button class="ghost toggle-keyword-rule" data-id="${rule.id}" type="button">${rule.is_active ? "停用" : "启用"}</button><button class="ghost danger delete-keyword-rule" data-id="${rule.id}" type="button">删除</button></div></div>`).join("");
}

function fuzzyMatch(value, query) {
  const text = value.toLocaleLowerCase();
  const search = query.trim().toLocaleLowerCase();
  if (!search || text.includes(search)) return true;
  let position = 0;
  return [...search].every((character) => {
    position = text.indexOf(character, position);
    if (position < 0) return false;
    position += 1;
    return true;
  });
}

function renderProviderModels() {
  const selectionText = [...state.selectedProviderModels].join(", ");
  const query = $("#model-provider-name").value === selectionText ? "" : $("#model-provider-name").value;
  const options = state.providerModels.filter((model) => fuzzyMatch(model, query)).slice(0, 80);
  const target = $("#provider-model-options");
  if (!state.providerModels.length) { target.innerHTML = ""; return; }
  if (!options.length) { target.innerHTML = '<p class="field-hint">没有匹配的模型，可继续手动输入 model ID。</p>'; return; }
  target.innerHTML = options.map((model) => `<button class="provider-model-option ${state.selectedProviderModels.has(model) ? "selected" : ""}" type="button" data-model="${escapeHtml(model)}" aria-pressed="${state.selectedProviderModels.has(model)}"><span class="selection-mark">${state.selectedProviderModels.has(model) ? "✓" : "+"}</span>${escapeHtml(model)}</button>`).join("");
}

function updateModelSelection() {
  const selected = [...state.selectedProviderModels];
  $("#model-selection-count").textContent = selected.length ? `已选择 ${selected.length} 个` : "未选择";
  $("#model-provider-name").value = selected.join(", ");
  renderProviderModels();
}

function resetModelForm() {
  $("#model-form").reset();
  $("#model-id").value = "";
  $("#model-active").checked = true;
  $("#model-input-price").value = "0";
  $("#model-output-price").value = "0";
  $("#model-submit").textContent = "保存模型";
  state.providerModels = [];
  state.selectedProviderModels = new Set();
  state.providerModelsLoading = false;
  $("#provider-model-options").innerHTML = "";
  $("#provider-model-status").textContent = "尚未加载模型列表。";
  $("#model-selection-count").textContent = "未选择";
}

function editModel(id) {
  const model = state.models.find((item) => item.id === id);
  if (!model) return;
  if (model.role === "redactor") { setMessage("Provider 脱敏模型已停用；请配置服务器本地脱敏环境变量，或删除旧配置。 "); return; }
  showView("models");
  $("#model-id").value = model.id;
  $("#model-name").value = model.name;
  $("#model-role").value = model.role;
  $("#model-base-url").value = model.base_url;
  $("#model-provider-name").value = model.model_name;
  $("#model-api-key").value = "";
  $("#model-input-price").value = model.input_price_per_million;
  $("#model-output-price").value = model.output_price_per_million;
  $("#model-active").checked = model.is_active;
  $("#model-submit").textContent = "更新模型";
  state.selectedProviderModels = new Set([model.model_name]);
  $("#model-selection-count").textContent = "已选择 1 个";
  $("#model-form").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function ensureProviderModels() {
  const status = $("#provider-model-status");
  const baseUrl = $("#model-base-url").value.trim();
  const apiKey = $("#model-api-key").value;
  const modelId = Number($("#model-id").value);
  if (state.providerModelsLoading || state.providerModels.length) return;
  if (!baseUrl) { status.textContent = "请先填写以 /v1 结尾的 Base URL。"; return; }
  if (!apiKey && !modelId) { status.textContent = "新模型需要先填写 API Key 才能自动获取列表。"; return; }
  state.providerModelsLoading = true;
  status.textContent = "正在读取 Provider 模型列表…";
  try {
    const result = modelId && !apiKey
      ? await api(`/api/models/${modelId}/available-models`, { method: "POST" })
      : await api("/api/provider-models", { method: "POST", body: JSON.stringify({ base_url: baseUrl, api_key: apiKey }) });
    state.providerModels = result.models;
    status.textContent = `已加载 ${result.models.length} 个模型；可搜索并点击选择。`;
    renderProviderModels();
  } catch (error) { status.textContent = error.message; state.providerModels = []; renderProviderModels(); } finally { state.providerModelsLoading = false; }
}

function clearProviderModels() {
  state.providerModels = [];
  state.selectedProviderModels = new Set();
  $("#model-selection-count").textContent = "未选择";
  $("#provider-model-options").innerHTML = "";
  $("#provider-model-status").textContent = "填写 Base URL 和 API Key 后，点击此区域会自动加载模型列表。";
}

function toggleProviderModel(model) {
  const role = $("#model-role").value;
  const isEditing = Boolean(Number($("#model-id").value));
  if (role !== "target" || isEditing) {
    state.selectedProviderModels = new Set([model]);
  } else if (state.selectedProviderModels.has(model)) {
    state.selectedProviderModels.delete(model);
  } else {
    state.selectedProviderModels.add(model);
  }
  updateModelSelection();
  const selected = state.selectedProviderModels.size;
  $("#provider-model-status").textContent = selected > 1 ? `已选择 ${selected} 个目标模型；保存时将创建多条目标模型配置。` : `已选择 ${selected || 0} 个模型。`;
}

function appendChat(kind, content) {
  const output = $("#chat-output");
  output.querySelector(".empty-state")?.remove();
  const message = document.createElement("div");
  message.className = `message ${kind}`;
  message.textContent = content;
  output.append(message);
  output.scrollTop = output.scrollHeight;
}

function appendPipeline(result) {
  const item = document.createElement("div");
  item.className = "pipeline-detail";
  const cost = result.cost_known ? `$${Number(result.total_cost).toFixed(6)}` : "待 Provider 返回完整 usage";
  const redaction = result.redaction_applied
    ? `<div><b>脱敏后：</b>${escapeHtml(result.redacted_message)}</div>`
    : "<div><b>脱敏：</b>未启用；原文不会写入审计记录</div>";
  item.innerHTML = `${redaction}<div><b>路由：</b>${escapeHtml(result.selected_model)} — ${escapeHtml(result.routing_reason)}</div><div><b>消费：</b>${cost} · ${result.prompt_tokens + result.completion_tokens} tokens</div>`;
  $("#chat-output").append(item);
}

async function refreshCalls() {
  const [calls, stats, evaluation] = await Promise.all([api("/api/calls"), api("/api/stats"), api("/api/evaluation")]);
  renderCalls(calls);
  $("#metric-calls").textContent = stats.total_calls || 0;
  $("#metric-success").textContent = stats.successful_calls || 0;
  $("#metric-cost").textContent = `$${Number(stats.total_cost || 0).toFixed(6)}`;
  $("#metric-cost-note").textContent = stats.unknown_cost_calls ? `${stats.unknown_cost_calls} 条调用未返回完整 usage` : "";
  renderEvaluation(evaluation);
}

async function initialise() {
  try {
    const user = await api("/api/auth/me");
    const csrf = await api("/api/auth/csrf");
    state.csrfToken = csrf.csrf_token;
    showApp(user);
    await loadDashboard();
  } catch (_) {
    const auth = await api("/api/auth/state");
    $("#auth-copy").textContent = auth.bootstrap_required ? "创建唯一的初始管理员账户。12–15 位密码需使用至少三类字符；16 位以上可使用长密码短语。" : "使用管理员账户登录。";
    $("#bootstrap-token-field").hidden = !auth.bootstrap_required || !auth.bootstrap_token_required;
    $("#bootstrap-token").required = Boolean(auth.bootstrap_required && auth.bootstrap_token_required);
    $("#auth-submit").textContent = auth.bootstrap_required ? "创建账户并进入控制台" : "登录";
    $("#auth-form").dataset.mode = auth.bootstrap_required ? "bootstrap" : "login";
    showAuth();
  }
}

$(".app-nav").addEventListener("click", (event) => { if (event.target.dataset.viewTarget) showView(event.target.dataset.viewTarget); });
$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const button = $("#auth-submit"); button.disabled = true; $("#auth-message").textContent = "";
  try {
    const isBootstrap = event.currentTarget.dataset.mode === "bootstrap";
    const request = { username: $("#auth-username").value.trim(), password: $("#auth-password").value };
    if (isBootstrap) request.bootstrap_token = $("#bootstrap-token").value;
    const result = await api(isBootstrap ? "/api/auth/bootstrap" : "/api/auth/login", { method: "POST", body: JSON.stringify(request) });
    state.csrfToken = result.csrf_token; showApp(result); await loadDashboard();
  } catch (error) { $("#auth-message").textContent = error.message; } finally { button.disabled = false; }
});

$("#logout-button").addEventListener("click", async () => { try { await api("/api/auth/logout", { method: "POST" }); } finally { showAuth(); await initialise(); } });
$("#change-password-button").addEventListener("click", () => { $("#password-form").reset(); $("#password-message").textContent = ""; $("#password-dialog").showModal(); });
$("#close-password-dialog").addEventListener("click", () => $("#password-dialog").close());
$("#password-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const message = $("#password-message"); message.textContent = "";
  try { const result = await api("/api/auth/password", { method: "PUT", body: JSON.stringify({ current_password: $("#current-password").value, new_password: $("#new-password").value }) }); state.csrfToken = result.csrf_token; $("#password-dialog").close(); setMessage("密码已更新，其他登录会话已失效。", "success"); } catch (error) { message.textContent = error.message; }
});

$("#model-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const id = Number($("#model-id").value);
  const data = { name: $("#model-name").value.trim(), role: $("#model-role").value, base_url: $("#model-base-url").value.trim(), api_key: $("#model-api-key").value, model_name: $("#model-provider-name").value.trim(), input_price_per_million: Number($("#model-input-price").value), output_price_per_million: Number($("#model-output-price").value), is_active: $("#model-active").checked };
  const selectedModels = [...state.selectedProviderModels];
  const modelNames = selectedModels.length ? selectedModels : [data.model_name];
  if (id && !data.api_key) delete data.api_key;
  if (!id && modelNames.length > 1 && data.role !== "target") { setMessage("多选仅支持目标模型；脱敏模型和路由模型一次只能选择一个。"); return; }
  try {
    if (!id && modelNames.length > 1) {
      const prefix = data.name;
      const models = modelNames.map((modelName) => ({ ...data, name: `${prefix} · ${modelName}`.slice(0, 80), model_name: modelName }));
      await api("/api/models/batch", { method: "POST", body: JSON.stringify({ models }) });
      setMessage(`已创建 ${models.length} 个目标模型配置。`, "success");
    } else {
      data.model_name = modelNames[0];
      await api(id ? `/api/models/${id}` : "/api/models", { method: id ? "PUT" : "POST", body: JSON.stringify(data) });
      setMessage("模型配置已保存。", "success");
    }
    resetModelForm(); await loadDashboard();
  } catch (error) { setMessage(error.message); }
});

$("#model-provider-name").addEventListener("focus", ensureProviderModels);
$("#model-provider-name").addEventListener("input", () => {
  const selectedText = [...state.selectedProviderModels].join(", ");
  if ($("#model-provider-name").value !== selectedText) {
    state.selectedProviderModels = new Set();
    $("#model-selection-count").textContent = "手动输入";
    renderProviderModels();
  }
  ensureProviderModels();
});
$("#model-base-url").addEventListener("input", clearProviderModels);
$("#model-api-key").addEventListener("input", clearProviderModels);
$("#model-role").addEventListener("change", () => {
  if ($("#model-role").value !== "target" && state.selectedProviderModels.size > 1) {
    state.selectedProviderModels = new Set([[...state.selectedProviderModels][0]]);
    updateModelSelection();
  }
});
$("#provider-model-options").addEventListener("click", (event) => {
  const option = event.target.closest("[data-model]");
  const model = option?.dataset.model;
  if (!model) return;
  toggleProviderModel(model);
});
$("#models-list").addEventListener("click", async (event) => {
  const id = Number(event.target.dataset.id); if (!id) return;
  if (event.target.classList.contains("edit-model")) editModel(id);
  if (event.target.classList.contains("test-model")) {
    event.target.disabled = true;
    try { const result = await api(`/api/models/${id}/test`, { method: "POST" }); const cost = result.cost_known ? `$${Number(result.total_cost).toFixed(6)}` : "usage 未完整返回"; setMessage(`${result.model_name} 连接成功：${result.response_preview}（${cost}）`, "success"); await refreshCalls(); } catch (error) { setMessage(error.message); } finally { event.target.disabled = false; }
  }
  if (event.target.classList.contains("delete-model") && confirm("删除此模型配置？调用历史不会删除。")) { try { await api(`/api/models/${id}`, { method: "DELETE" }); resetModelForm(); await loadDashboard(); setMessage("模型配置已删除。", "success"); } catch (error) { setMessage(error.message); } }
});
$("#reset-model-form").addEventListener("click", resetModelForm);
$("#restore-default-rules").addEventListener("click", async () => {
  if (!confirm("将用推荐规则覆盖当前编辑框内容；需点击“保存规则”才会生效。")) return;
  try { const defaults = await api("/api/rules/defaults"); $("#redaction-rule").value = defaults.redaction; $("#routing-rule").value = defaults.routing; setMessage("已填入推荐规则，请检查后保存。", "success"); } catch (error) { setMessage(error.message); }
});
$("#create-service-key").addEventListener("click", async () => {
  if (!confirm("生成新 Key 会立即使旧 Key 失效，是否继续？")) return;
  try {
    const result = await api("/api/service-key", { method: "POST" });
    $("#service-key-value").textContent = result.api_key;
    $("#service-key-reveal").hidden = false;
    renderServiceApi(await api("/api/service-key"));
    setMessage("服务 API Key 已生成，请立即复制。", "success");
  } catch (error) { setMessage(error.message); }
});
$("#revoke-service-key").addEventListener("click", async () => {
  if (!confirm("撤销后，所有使用该 Key 的 Agent 与外部客户端都会立即失效。是否继续？")) return;
  try {
    await api("/api/service-key", { method: "DELETE" });
    $("#service-key-reveal").hidden = true;
    renderServiceApi(await api("/api/service-key"));
    setMessage("服务 API Key 已撤销。", "success");
  } catch (error) { setMessage(error.message); }
});
$("#copy-service-key").addEventListener("click", async () => {
  const key = $("#service-key-value").textContent;
  if (!key) return;
  try { await navigator.clipboard.writeText(key); setMessage("服务 API Key 已复制。", "success"); } catch (_) { setMessage("浏览器未允许自动复制，请手动复制 Key。", "error"); }
});
$("#rules-form").addEventListener("submit", async (event) => { event.preventDefault(); try { await api("/api/rules", { method: "PUT", body: JSON.stringify({ redaction: $("#redaction-rule").value, routing: $("#routing-rule").value }) }); setMessage("规则已保存。", "success"); } catch (error) { setMessage(error.message); } });
$("#keyword-rule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/keyword-rules", { method: "POST", body: JSON.stringify({ phrase: $("#keyword-phrase").value.trim(), replacement: $("#keyword-replacement").value.trim(), is_fuzzy: $("#keyword-fuzzy").checked }) });
    event.currentTarget.reset(); $("#keyword-replacement").value = "[KEYWORD]";
    state.keywordRules = await api("/api/keyword-rules"); renderKeywordRules(); setMessage("关键词规则已添加。", "success");
  } catch (error) { setMessage(error.message); }
});
$("#keyword-rules-list").addEventListener("click", async (event) => {
  const id = Number(event.target.dataset.id); if (!id) return;
  const rule = state.keywordRules.find((item) => item.id === id); if (!rule) return;
  try {
    if (event.target.classList.contains("delete-keyword-rule")) {
      await api(`/api/keyword-rules/${id}`, { method: "DELETE" });
      setMessage("关键词规则已删除。", "success");
    } else if (event.target.classList.contains("toggle-keyword-rule")) {
      await api(`/api/keyword-rules/${id}`, { method: "PUT", body: JSON.stringify({ is_active: !rule.is_active }) });
      setMessage("关键词规则状态已更新。", "success");
    } else return;
    state.keywordRules = await api("/api/keyword-rules"); renderKeywordRules();
  } catch (error) { setMessage(error.message); }
});
$("#chat-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const input = $("#chat-message"), button = $("#chat-submit"), message = input.value.trim(); if (!message) return;
  appendChat("user", message); input.value = ""; button.disabled = true;
  try {
    const context = state.chatHistory.slice(-16);
    const result = await api("/api/chat", { method: "POST", body: JSON.stringify({ message, context }) });
    appendPipeline(result); appendChat("assistant", result.answer);
    state.chatHistory.push({ role: "user", content: message }, { role: "assistant", content: result.answer });
    if (state.chatHistory.length > 16) state.chatHistory = state.chatHistory.slice(-16);
    await refreshCalls();
  } catch (error) { appendChat("assistant", `调用失败：${error.message}`); await refreshCalls(); } finally { button.disabled = false; }
});
$("#chat-message").addEventListener("keydown", (event) => {
  if (event.key !== "Enter" || event.shiftKey || event.ctrlKey || event.altKey || event.metaKey || event.isComposing) return;
  event.preventDefault();
  if (!$("#chat-submit").disabled) $("#chat-form").requestSubmit();
});
$("#clear-chat-context").addEventListener("click", () => {
  state.chatHistory = [];
  $("#chat-output").innerHTML = '<div class="empty-state">上下文已清除。后续消息将作为新的对话发送。</div>';
  setMessage("聊天上下文已清除；审计记录未改变。", "success");
});
$("#refresh-calls").addEventListener("click", () => refreshCalls().catch((error) => setMessage(error.message)));
$("#clear-calls").addEventListener("click", async () => { if (!confirm("永久清除全部调用记录与已记录的消费？此操作不可撤销。")) return; try { const result = await api("/api/calls", { method: "DELETE" }); await refreshCalls(); setMessage(`已清除 ${result.deleted_count} 条调用记录。`, "success"); } catch (error) { setMessage(error.message); } });
initialise().catch((error) => { $("#auth-copy").textContent = `无法启动：${error.message}`; });
