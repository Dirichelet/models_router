"""Local development entry point for Models Router."""

import uvicorn


if __name__ == "__main__":
    # The development workspace is accessed through its container/network
    # gateway, so loopback-only binding makes the UI unreachable in a browser.
    uvicorn.run("app.main:app", host="0.0.0.0", port=9898, reload=True)
