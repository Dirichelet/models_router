const state = { csrfToken: null, models: [] };

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#039;", '"': "&quot;" })[char]);

function setMessage(message, kind = "error") {
  const target = $("#app-message");
  target.textContent = message;
  target.className = `app-message ${kind === "success" ? "success" : ""}`;
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
}

function showApp(user) {
  $("#auth-panel").hidden = true;
  $("#app-shell").hidden = false;
  $("#current-user").textContent = user.username;
}

async function loadDashboard() {
  const [models, rules, calls, stats] = await Promise.all([api("/api/models"), api("/api/rules"), api("/api/calls"), api("/api/stats")]);
  state.models = models;
  renderModels();
  renderCalls(calls);
  $("#redaction-rule").value = rules.redaction || "";
  $("#routing-rule").value = rules.routing || "";
  $("#metric-calls").textContent = stats.total_calls || 0;
  $("#metric-success").textContent = stats.successful_calls || 0;
  $("#metric-cost").textContent = `$${Number(stats.total_cost || 0).toFixed(6)}`;
}

function renderModels() {
  const container = $("#models-list");
  if (!state.models.length) {
    container.innerHTML = '<div class="empty-state">尚未配置模型。API Key 仅以加密形式保存在服务器。</div>';
    return;
  }
  container.innerHTML = state.models.map((model) => `
    <div class="model-row">
      <div><h3>${escapeHtml(model.name)} ${model.is_active ? "" : "<span class=\"muted\">(已停用)</span>"}</h3>
      <p>${escapeHtml(model.role)} · ${escapeHtml(model.model_name)} · $${Number(model.input_price_per_million).toFixed(4)}/$${Number(model.output_price_per_million).toFixed(4)} 每百万 token</p></div>
      <div class="model-actions"><button class="ghost edit-model" data-id="${model.id}" type="button">编辑</button><button class="ghost danger delete-model" data-id="${model.id}" type="button">删除</button></div>
    </div>`).join("");
}

function renderCalls(calls) {
  const table = $("#calls-table");
  if (!calls.length) { table.innerHTML = '<tr><td colspan="5" class="muted">暂无调用记录</td></tr>'; return; }
  table.innerHTML = calls.map((call) => `
    <tr><td>${escapeHtml(new Date(call.created_at).toLocaleString())}</td><td>${escapeHtml(call.selected_model_name || "—")}</td>
    <td title="${escapeHtml(call.redacted_message || call.error_message || "")}">${escapeHtml((call.redacted_message || call.error_message || "—").slice(0, 180))}</td>
    <td>$${Number(call.total_cost || 0).toFixed(6)}<br><span class="muted">${call.prompt_tokens + call.completion_tokens} tokens</span></td>
    <td class="status-${escapeHtml(call.status)}">${escapeHtml(call.status)}</td></tr>`).join("");
}

function resetModelForm() {
  $("#model-form").reset();
  $("#model-id").value = "";
  $("#model-active").checked = true;
  $("#model-input-price").value = "0";
  $("#model-output-price").value = "0";
  $("#model-submit").textContent = "保存模型";
}

function editModel(id) {
  const model = state.models.find((item) => item.id === id);
  if (!model) return;
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
  $("#model-form").scrollIntoView({ behavior: "smooth", block: "center" });
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
  item.innerHTML = `<div><b>脱敏后：</b>${escapeHtml(result.redacted_message)}</div><div><b>路由：</b>${escapeHtml(result.selected_model)} — ${escapeHtml(result.routing_reason)}</div><div><b>消费：</b>$${Number(result.total_cost).toFixed(6)} · ${result.prompt_tokens + result.completion_tokens} tokens</div>`;
  $("#chat-output").append(item);
}

async function refreshCalls() {
  const [calls, stats] = await Promise.all([api("/api/calls"), api("/api/stats")]);
  renderCalls(calls);
  $("#metric-calls").textContent = stats.total_calls || 0;
  $("#metric-success").textContent = stats.successful_calls || 0;
  $("#metric-cost").textContent = `$${Number(stats.total_cost || 0).toFixed(6)}`;
}

async function initialise() {
  try {
    const user = await api("/api/auth/me");
    showApp(user);
    await loadDashboard();
  } catch (_) {
    const auth = await api("/api/auth/state");
    $("#auth-copy").textContent = auth.bootstrap_required ? "创建唯一的初始管理员账户。密码至少 12 位。" : "使用管理员账户登录。";
    $("#auth-submit").textContent = auth.bootstrap_required ? "创建账户并进入控制台" : "登录";
    $("#auth-form").dataset.mode = auth.bootstrap_required ? "bootstrap" : "login";
    showAuth();
  }
}

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = $("#auth-submit"); button.disabled = true;
  $("#auth-message").textContent = "";
  try {
    const body = JSON.stringify({ username: $("#auth-username").value.trim(), password: $("#auth-password").value });
    const route = event.currentTarget.dataset.mode === "bootstrap" ? "/api/auth/bootstrap" : "/api/auth/login";
    const result = await api(route, { method: "POST", body });
    state.csrfToken = result.csrf_token;
    showApp(result);
    await loadDashboard();
  } catch (error) { $("#auth-message").textContent = error.message; } finally { button.disabled = false; }
});

$("#logout-button").addEventListener("click", async () => {
  try { await api("/api/auth/logout", { method: "POST" }); } finally { showAuth(); await initialise(); }
});

$("#model-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = Number($("#model-id").value);
  const data = {
    name: $("#model-name").value.trim(), role: $("#model-role").value, base_url: $("#model-base-url").value.trim(),
    api_key: $("#model-api-key").value, model_name: $("#model-provider-name").value.trim(),
    input_price_per_million: Number($("#model-input-price").value), output_price_per_million: Number($("#model-output-price").value),
    is_active: $("#model-active").checked,
  };
  if (id && !data.api_key) delete data.api_key;
  try {
    await api(id ? `/api/models/${id}` : "/api/models", { method: id ? "PUT" : "POST", body: JSON.stringify(data) });
    setMessage("模型配置已保存。", "success"); resetModelForm(); await loadDashboard();
  } catch (error) { setMessage(error.message); }
});

$("#models-list").addEventListener("click", async (event) => {
  const id = Number(event.target.dataset.id);
  if (!id) return;
  if (event.target.classList.contains("edit-model")) editModel(id);
  if (event.target.classList.contains("delete-model") && confirm("删除此模型配置？调用历史不会删除。")) {
    try { await api(`/api/models/${id}`, { method: "DELETE" }); resetModelForm(); await loadDashboard(); setMessage("模型配置已删除。", "success"); } catch (error) { setMessage(error.message); }
  }
});

$("#reset-model-form").addEventListener("click", resetModelForm);
$("#rules-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/rules", { method: "PUT", body: JSON.stringify({ redaction: $("#redaction-rule").value, routing: $("#routing-rule").value }) });
    setMessage("规则已保存。", "success");
  } catch (error) { setMessage(error.message); }
});

$("#chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#chat-message"), button = $("#chat-submit"), message = input.value.trim();
  if (!message) return;
  appendChat("user", message); input.value = ""; button.disabled = true;
  try {
    const result = await api("/api/chat", { method: "POST", body: JSON.stringify({ message }) });
    appendPipeline(result); appendChat("assistant", result.answer); await refreshCalls();
  } catch (error) { appendChat("assistant", `调用失败：${error.message}`); await refreshCalls(); } finally { button.disabled = false; }
});

$("#refresh-calls").addEventListener("click", () => refreshCalls().catch((error) => setMessage(error.message)));
initialise().catch((error) => { $("#auth-copy").textContent = `无法启动：${error.message}`; });
