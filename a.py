from transformers import pipeline

import torch
from transformers import pipeline

pipe = pipeline(
    task="token-classification",
    model="openai/privacy-filter",
    device='cpu',
    torch_dtype=torch.float16,
    aggregation_strategy="simple",
)

text = "My name is Alice Smith and my email is alice@example.com."
print(pipe(text))
pipe('我的电话是123，密码：2498')