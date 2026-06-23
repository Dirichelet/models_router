# Models Router

一个面向 OpenAI 兼容接口的隐私优先模型路由器：消息会先经过脱敏模型，再交由路由模型在多个目标模型中选择合适的调用目标。控制台显示脱敏内容、选中的模型、token 用量和按已配置价格计算的实际消费。

## 使用方法（本地开发，uv）

安装 [uv](https://docs.astral.sh/uv/) 后，在项目目录执行：

```bash
uv sync --dev

export APP_ENV=development
export COOKIE_SECURE=false

uv run python main.py
```

开发模式首次启动会在 `data/.dev-fernet.key` 生成并持久保存本地加密密钥；后续启动会复用它。不要删除该文件或每次手动更换 `FERNET_KEY`，否则已保存的模型 API Key 需要重新填写。

打开 `http://127.0.0.1:9898`。开发模式不要求启动令牌。

### 首次配置

1. 创建唯一的管理员账户。密码至少 12 位；12–15 位需包含至少三类字符，16 位以上可使用长密码短语。
2. 在“模型配置”至少创建并启用一个目标模型。脱敏模型和路由模型均为可选：未配置脱敏模型时消息原样传给后续模型，但仍不会写入审计记录；未配置路由模型时，服务会按问题难度选择低、中或高费率候选模型。Base URL 必须以 `/v1` 结尾，例如 `https://openrouter.ai/api/v1`。
3. 填写 Base URL 和 API Key 后，点击或聚焦“Provider 模型”会自动获取模型列表；可按厂商或模型名模糊搜索。脱敏模型和路由模型单选，目标模型可多选并在保存时自动创建多条目标模型配置。
4. 分别点击“测试”确认模型连通性。API Key 只以加密形式保存，编辑时不会回显。若模型卡片提示“API Key 需重填”，点击编辑并重新输入该模型的 API Key 后保存即可。
5. 在“提示词规则”中调整 Markdown 规则；可点击“恢复推荐规则”填入详细的脱敏与路由规则。
6. 页面显示“已就绪”后，在聊天窗口输入消息。浏览器会在内存中保留最近 8 轮对话作为上下文，可用“清除上下文”开始新对话；这些原始上下文不会写入数据库。界面会展示脱敏结果（如启用）、路由选择、token、消费和审计记录。

原始消息不会写进审计记录；如需删除已保存的脱敏内容和消费记录，可在“最近调用”区域点击“清除记录”。

### 可选：从后端环境变量加载本地 GGUF 脱敏/分类模型

本地模型不在网页上传或配置，避免将模型路径和运行参数暴露给浏览器。仅支持 GGUF 文件，使用 `llama-cpp-python` 运行。先安装可选依赖：

```bash
uv sync --extra local-gguf
```

启动前设置绝对路径；本地模型会优先于网页中同角色的 Provider 配置。`LOCAL_REDACTOR_MODEL_PATH` 用于脱敏，`LOCAL_CLASSIFIER_MODEL_PATH` 用于分类/路由；任一变量未设置时，会分别回退到网页 Provider 模型或默认策略。

```bash
export LOCAL_REDACTOR_MODEL_PATH=/absolute/path/redactor.gguf
export LOCAL_CLASSIFIER_MODEL_PATH=/absolute/path/classifier.gguf
export LOCAL_GGUF_CHAT_FORMAT=chatml       # 按模型模板调整，可省略
export LOCAL_GGUF_CONTEXT_TOKENS=4096
export LOCAL_GGUF_GPU_LAYERS=0             # CPU 为 0；按 llama.cpp 环境调整
export LOCAL_GGUF_THREADS=0                # 0 表示 llama.cpp 默认值

uv run python main.py
```

路径不存在、模型加载失败或未安装 `local-gguf` 依赖时，页面会禁用聊天并显示具体原因。不要把本地模型路径或这些环境变量放到网页表单中。

## 供其他 Agent / Chat 客户端调用

在网页的“服务 API”页签生成专用 API Key。完整 Key 只显示一次，妥善保存。然后将其他客户端的 OpenAI Base URL 指向本服务的 `/v1`：本地开发示例为 `http://127.0.0.1:9898/v1`。

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:9898/v1",
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

服务实现了 `GET /v1/models` 和非流式 `POST /v1/chat/completions`，返回标准 `choices[0].message.content` 与 `usage`。文本内容数组、`system`、`assistant` 和 `tool` 消息会作为对话上下文处理；是否脱敏取决于当前脱敏配置。暂不支持 `stream=true` 或服务端工具执行。

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
