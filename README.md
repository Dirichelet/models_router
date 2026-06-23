# Models Router

一个面向 OpenAI 兼容接口的隐私优先模型路由器：消息会先经过脱敏模型，再交由路由模型在多个目标模型中选择合适的调用目标。控制台显示脱敏内容、选中的模型、token 用量和按已配置价格计算的实际消费。

## 运行

1. 复制环境变量模板并设置公网域名、ACME 邮箱和新的 `FERNET_KEY`：

   ```bash
   cp .env.example .env
   ```

2. 为 `CADDY_DOMAIN` 配置 DNS A/AAAA 记录，并启动：

   ```bash
   docker compose up --build -d
   ```

3. 打开 `https://<CADDY_DOMAIN>`，在网页中创建唯一的初始管理员账户；随后在网页中录入脱敏模型、路由模型、目标模型及规则。

模型 API Key 使用 `FERNET_KEY` 加密后才写入 SQLite。原始用户消息不会存入调用记录；记录中仅保留脱敏后的消息。不要提交 `.env`、数据库卷或任何真实 Provider 密钥。

## 本地开发

开发环境也必须设置一个独立的 `FERNET_KEY`：

```bash
export APP_ENV=development
export COOKIE_SECURE=false
export FERNET_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
uv sync --dev
uv run python main.py
```

生产环境应仅经 Compose 中的 Caddy 暴露服务；应用容器不直接发布端口。
