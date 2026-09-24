"""演示时钟：真实时间 + 可调偏移，用于时限合约/超时预警的演示推进。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from gunreg.common import Clock


class DemoClock(Clock):
    """真实墙上时间叠加一个可推进的偏移量。

    业务事件的时间戳均取自系统时钟；监管工作台「时间推进」按钮
    增大偏移量，即可让已领用枪支逐步超时，从而演示三级预警闭环。
    """

    def __init__(self) -> None:
        self.offset = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(timezone.utc) + self.offset

    def advance(self, **kwargs) -> None:
        self.offset += timedelta(**kwargs)

    def baseline(self) -> str:
        """当前偏移量下演示时间（不含偏移的真实时间）。"""
        return (datetime.now(timezone.utc) + self.offset).isoformat()