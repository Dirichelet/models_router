"""Local development entry point for Models Router."""

import os

import uvicorn


def server_address() -> tuple[str, int]:
    host = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
    try:
        port = int(os.getenv("PORT", "9900"))
    except ValueError as exc:
        raise RuntimeError("PORT must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("PORT must be an integer between 1 and 65535")
    return host, port


if __name__ == "__main__":
    host, port = server_address()
    uvicorn.run("app.main:app", host=host, port=port, reload=True)
