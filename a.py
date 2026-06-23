"""Verify the production local-only redaction path with a pre-downloaded model."""

from __future__ import annotations

import os
from pathlib import Path

from app.redaction import LocalRedactorOptions, local_redact


if __name__ == "__main__":
    model_path = Path(os.environ["LOCAL_REDACTOR_MODEL_PATH"]).expanduser().resolve()
    result = local_redact(
        LocalRedactorOptions(
            privacy_filter_path=model_path,
            chinese_ner_path=None,
            device=os.getenv("LOCAL_REDACTOR_DEVICE", "cpu"),
            min_score=float(os.getenv("LOCAL_REDACTOR_MIN_SCORE", "0.5")),
        ),
        "我的姓名是张三，手机号是 13800138000，邮箱是 alice@example.com。",
    )
    print(result)
