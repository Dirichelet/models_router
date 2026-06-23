# Models Router

一个面向 OpenAI 兼容接口的隐私优先模型路由器：消息会先经过脱敏模型，再交由路由模型在多个目标模型中选择合适的调用目标。控制台显示脱敏内容、选中的模型、token 用量和按已配置价格计算的实际消费。

## 使用方法（本地开发，uv）

安装 [uv](https://docs.astral.sh/uv/) 后，在项目目录执行：

```bash
uv sync --dev

export APP_ENV=development
export COOKIE_SECURE=false
export FERNET_KEY="$(uv run python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"

uv run python main.py
```

打开 `http://127.0.0.1:8000`。开发模式不要求启动令牌。

### 首次配置

1. 创建唯一的管理员账户。密码至少 12 位；12–15 位需包含至少三类字符，16 位以上可使用长密码短语。
2. 在“模型配置”创建并启用三个角色：一个脱敏模型、一个路由模型和至少一个目标模型。每项都在网页填写 OpenAI 兼容地址、Provider 模型名、API Key 与每百万 token 的价格。
3. 分别点击“测试”确认模型连通性。API Key 只以加密形式保存，编辑时不会回显。
4. 在“脱敏与路由规则”中调整 Markdown 规则。默认规则可直接使用。
5. 页面显示“已就绪”后，在聊天窗口输入消息。界面会展示脱敏结果、路由模型选择、token、消费和审计记录。

原始消息不会写进审计记录；如需删除已保存的脱敏内容和消费记录，可在“最近调用”区域点击“清除记录”。

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
