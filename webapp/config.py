"""演示/生产开关配置。

- DEMO：演示接口（totp-demo、时钟推进）是否开放；
- COOKIE_SECURE：会话 Cookie 是否仅限 HTTPS（生产应为 True）。
"""
from __future__ import annotations

import os


def _flag(name: str, default: bool) -> bool:
    v = os.environ.get(name, "")
    if v == "":
        return default
    return v.lower() not in ("0", "false", "no", "off")


DEMO = _flag("GUNREG_DEMO", True)
COOKIE_SECURE = _flag("GUNREG_COOKIE_SECURE", False)


def require_demo() -> None:
    """演示专用接口（口令直显/时钟推进）在生产开关关闭时一律拒绝。"""
    if not DEMO:
        from gunreg.common import PermissionDenied

        raise PermissionDenied("演示接口未启用")