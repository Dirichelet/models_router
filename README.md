# Models Router

一个面向 OpenAI 兼容接口的隐私优先模型路由器：消息会先经过脱敏模型，再交由路由模型在多个目标模型中选择合适的调用目标。控制台显示脱敏内容、选中的模型、token 用量和按已配置价格计算的实际消费。

## 使用方法（本地开发，uv）

安装 [uv](https://docs.astral.sh/uv/) 后，在项目目录执行：

```bash
uv sync --dev

export APP_ENV=development
export COOKIE_SECURE=false
# 如部署环境通过 HTTP(S)_PROXY / ALL_PROXY 出网，保持默认 true
export PROVIDER_TRUST_ENV=true
# 选择一个未被占用的端口；本项目默认 9900
export PORT=9900

uv run python main.py
```

开发模式首次启动会在 `data/.dev-fernet.key` 生成并持久保存本地加密密钥；后续启动会复用它。不要删除该文件或每次手动更换 `FERNET_KEY`，否则已保存的模型 API Key 需要重新填写。

启动日志会显示实际端口。随后在工作区的“端口/Ports”面板打开该端口（上例为 9900）；同一台机器本地运行时访问 `http://127.0.0.1:9900`。若端口已被占用，换成任意空闲端口，例如 `export PORT=9910` 后重新执行启动命令。开发模式不要求启动令牌，且会允许工作区预览网关；生产部署必须设置 `TRUSTED_HOSTS`。

### 首次配置

1. 创建唯一的管理员账户。密码至少 12 位；12–15 位需包含至少三类字符，16 位以上可使用长密码短语。
2. 在“模型配置”至少创建并启用一个目标模型。脱敏模型只在服务器本地运行，不会调用 Provider；未配置本地脱敏时消息原样传给后续模型，但原文仍不会写入审计记录。路由模型可选；未配置时服务会按问题难度选择低、中或高费率候选模型。Base URL 必须以 `/v1` 结尾，例如 `https://openrouter.ai/api/v1`。
3. 填写 Base URL 和 API Key 后，点击“Provider 模型 / 搜索”输入框会自动获取模型列表；直接输入名称、厂商或任意字符即可模糊筛选。路由模型单选，目标模型可多选并在保存时自动创建多条目标模型配置。
4. 分别点击“测试”确认模型连通性。API Key 只以加密形式保存，编辑时不会回显。若模型卡片提示“API Key 需重填”，点击编辑并重新输入该模型的 API Key 后保存即可。
5. 在“本地脱敏与路由规则”中管理关键词规则。关键词可精确或模糊匹配（忽略大小写、空格、句点、下划线、连字符），会在本地模型识别前替换；路由 Markdown 规则用于 Provider 或本地 GGUF 路由模型。
6. 页面显示“已就绪”后，在聊天窗口输入消息。浏览器会在内存中保留最近 8 轮对话作为上下文，可用“清除上下文”开始新对话；这些原始上下文不会写入数据库。界面会展示脱敏结果（如启用）、路由选择、token、消费和审计记录。

原始消息不会写进审计记录；如需删除已保存的脱敏内容和消费记录，可在“最近调用”区域点击“清除记录”。

### 忘记管理员密码

不要删除 `data/`，否则会丢失模型配置和已加密的 Provider Key。在项目根目录运行以下本机恢复命令；它会交互式读取新密码（不会出现在终端历史中），并使该账户所有已登录浏览器会话失效：

```bash
uv run python scripts/reset_admin_password.py --username <管理员用户名>
```

### 可选：从后端环境变量加载本地脱敏/分类模型

本地模型不在网页上传或配置，避免将模型路径和运行参数暴露给浏览器。脱敏使用 `transformers` 本地目录，并强制 `local_files_only=True`：运行期不会下载模型或发送内容到 Provider。链路为 Regex（手机号、身份证、邮箱、密钥、IP 等）→ `openai/privacy-filter` → 可选中文 NER。若服务器已有官方 Hugging Face 缓存（`models--openai--privacy-filter`），会自动发现并启用；否则通过环境变量指定已下载目录。

```bash
export LOCAL_REDACTOR_MODEL_PATH=/absolute/path/openai-privacy-filter
export LOCAL_CHINESE_NER_MODEL_PATH=/absolute/path/chinese-ner  # 可选
export LOCAL_REDACTOR_DEVICE=cpu                                # 或 cuda:0
export LOCAL_REDACTOR_MIN_SCORE=0.5

uv run python main.py
```

本地 GGUF 只用于可选路由/分类模型，需要安装额外依赖：

```bash
uv sync --extra local-gguf
```

```bash
export LOCAL_CLASSIFIER_MODEL_PATH=/absolute/path/classifier.gguf
export LOCAL_GGUF_CHAT_FORMAT=chatml       # 按模型模板调整，可省略
export LOCAL_GGUF_CONTEXT_TOKENS=4096
export LOCAL_GGUF_GPU_LAYERS=0             # CPU 为 0；按 llama.cpp 环境调整
export LOCAL_GGUF_THREADS=0                # 0 表示 llama.cpp 默认值

uv run python main.py
```

路径不存在、模型加载失败或缺少依赖时，页面会禁用聊天并显示具体原因。不要把本地模型路径或这些环境变量放到网页表单中。

Provider 请求默认继承运行环境的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 与 `NO_PROXY`，以支持受限网络的正常出网；不需要代理或要求直连时设置 `PROVIDER_TRUST_ENV=false` 后重启服务。

### 脱敏评测

项目内置基于 [MultiPriv-PII](https://github.com/CyberChangAn/MultiPriv-PII) 的可重复本地评测。首次运行只会下载公开基准数据到 `tests/.multipriv-cache/`（已被 Git 忽略）；评测不会调用 Provider，也不会上传业务消息。它按结构化 PII 字段和实际替换区间计算 precision、recall、F1，并默认要求三项均不低于 0.85：

```bash
uv run python tests/eval_redaction.py
```

已有缓存且需要禁止联网时：

```bash
uv run python tests/eval_redaction.py --offline
```

可用 `--threshold 0.90` 提高发布门禁。评测规则会校验其追踪的替换结果与生产 `app.redaction` 的规则输出完全一致，避免评测逻辑与运行逻辑漂移。

## 供其他 Agent / Chat 客户端调用

在网页的“服务 API”页签生成专用 API Key。完整 Key 只显示一次，妥善保存。然后将其他客户端的 OpenAI Base URL 指向本服务的 `/v1`：本地开发示例为 `http://127.0.0.1:9900/v1`。

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:9900/v1",
    api_key="mr_从服务API页面生成的Key",
)

response = client.chat.completions.create(
    model="models-router",
    messages=[
        {"role": "system", "content": "你是一个简洁的助手。"},
        {"role": "user", "content": "请总结这段内容。"},
    ],
)
print(response.choices[0].message.content)
```

服务实现了 `GET /v1/models` 和 `POST /v1/chat/completions`，支持 `stream=true` 流式输出，非流式返回标准 `choices[0].message.content` 与 `usage`。文本内容数组、`system`、`assistant` 和 `tool` 消息会作为对话上下文处理；是否脱敏取决于当前脱敏配置。默认最大拼接上下文长度为 `MAX_MESSAGE_CHARS=200000`，适配 Kilo、OpenWebUI 等会发送较长 system prompt/environment details 的 agent 客户端。暂不执行客户端提交的工具调用。

## 仅本地 Agent 调用（Docker Compose）

如果这个服务只给同一台宿主机上的 Kilo、OpenWebUI、Dify、其它 agent 或本机脚本调用，不需要域名、Caddy、HTTPS 和公网 80/443 端口。仓库提供了 `compose.local.yml`，它只把服务发布到宿主机回环地址 `127.0.0.1`，局域网和公网都不能直接访问。

1. 生成本地部署环境变量：

   ```bash
    FERNET_KEY="$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")"
    BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
    
    cat > .env.local <<EOF
    FERNET_KEY=$FERNET_KEY
    BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
    APP_ENV=production
    COOKIE_SECURE=false
    TRUSTED_HOSTS=localhost,127.0.0.1
    MAX_MESSAGE_CHARS=200000
    PROVIDER_TRUST_ENV=true
    EOF
   ```

   `COOKIE_SECURE=false` 是因为本地方案使用 HTTP；`FERNET_KEY` 后续必须保持不变，否则已保存的 Provider API Key 无法解密。`.env.local` 不要提交到 Git。

2. 校验本地 Compose 配置：

   ```bash
   docker compose --env-file .env.local -f compose.local.yml config
   ```

3. 启动：

   ```bash
   docker compose --env-file .env.local -f compose.local.yml up --build -d
   ```

   默认宿主机端口是 `9900`。如果被占用，在 `.env.local` 里增加一行 `LOCAL_PORT=9911` 后重启。
   如果 `docker ps` 或启动时报 `permission denied while trying to connect to the docker API at unix:///var/run/docker.sock`，说明当前 Linux 用户没有 Docker daemon 权限。把当前用户加入 `docker` 组并重新登录 SSH：

   ```bash
   sudo usermod -aG docker "$USER"
   ```

4. 首次打开控制台：

   ```text
   http://127.0.0.1:9900
   ```

   使用 `.env.local` 中的 `BOOTSTRAP_TOKEN` 创建管理员账号，在网页里配置至少一个目标模型，然后到“服务 API”页签生成 `mr_...` API Key。

5. 本机其它 agent 的 OpenAI 兼容配置：

   ```text
   Base URL: http://127.0.0.1:9900/v1
   API Key:  mr_服务API页面生成的Key
   Model:    models-router
   ```

   这里的 `127.0.0.1` 指宿主机。宿主机上的客户端、脚本和 agent 都用这个地址。如果 agent 也跑在同一个 Compose 项目或同一个 Docker network 里，可以不通过宿主机端口，直接使用容器内地址 `http://app:8000/v1`；如果是另一个独立 Compose 项目，建议把两个服务加入同一个 external network，并给本服务设置固定 network alias，再让 agent 访问 `http://models-router:8000/v1`。

常用维护命令：

```bash
docker compose --env-file .env.local -f compose.local.yml logs -f app
docker compose --env-file .env.local -f compose.local.yml ps
docker compose --env-file .env.local -f compose.local.yml down
```

只停止服务不会删除 `router_data` 卷；模型配置、管理员账号、服务 API Key 和 ModelScope 脱敏模型缓存都会保留。如需彻底清空本地部署数据，确认无误后再执行 `docker compose --env-file .env.local -f compose.local.yml down -v`。

## 公网部署（Docker Compose）

1. 复制环境变量模板并设置公网域名、ACME 邮箱、新的 `FERNET_KEY` 与随机 `BOOTSTRAP_TOKEN`：

   ```bash
   cp .env.example .env
   ```

2. 为 `CADDY_DOMAIN` 配置 DNS A/AAAA 记录，并启动：

   ```bash
   docker compose up --build -d
   ```

3. 打开 `https://<CADDY_DOMAIN>`，在网页中输入 `BOOTSTRAP_TOKEN` 创建唯一的初始管理员账户；随后在网页中录入脱敏模型、路由模型、目标模型及规则。首个账户创建后该令牌不再可用于注册，但应继续作为部署密钥保留。

模型 API Key 使用 `FERNET_KEY` 加密后才写入 SQLite。原始用户消息不会存入调用记录；记录中仅保留脱敏后的消息。不要提交 `.env`、数据库卷或任何真实 Provider 密钥。

生产环境应仅经 Compose 中的 Caddy 暴露服务；应用容器不直接发布端口。
