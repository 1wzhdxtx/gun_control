"""标识体系（核心机制一：一枪一码）。

- 整枪码：制造企业代码 + 枪种代码 + 制造年份 + 生产流水号 + 校验位
  与 GA 1258 枪号保持可映射；全生命周期不变。
- 散件码：整枪码前缀 + 部件类别码 + 件序号（从属式编码）。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .common import ValidationError

# 枪种代码（示例，映射 GA/T 624 语义）
CALIBER_KIND = {
    "手枪": "P",
    "步枪": "R",
    "猎枪": "H",
    "运动步枪": "S",
    "气手枪": "G",
    "气步枪": "T",
}

# 部件类别码
PART_CATEGORY = {
    "枪管": "BR",
    "撞针": "ST",
    "瞄具": "SI",
    "弹匣": "MG",
    "气瓶": "CY",
    "枪身": "RC",
    "扳机组": "TR",
}

# 制造企业代码表（前两位）
MAKERS = {
    "云南西南": "YN",
    "北方装备": "BF",
    "某运动器材厂": "SP",
}


def _check_digit(body: str) -> str:
    """ISO 7064 MOD 11-10 校验位。"""
    total = 0
    for ch in body:
        if ch.isdigit():
            total = (total + int(ch)) * 2 % 11
        else:
            total = (total + (ord(ch) - ord("A") + 10)) * 2 % 11
    check = (12 - total % 11) % 11
    return "X" if check == 10 else str(check)


@dataclass(frozen=True)
class GunCode:
    """整枪码：MAKER-CALIBER-YEAR-SERIAL-CHECK（与枪号可映射）。"""

    maker: str    # 企业代码2位
    kind: str     # 枪种代码1位
    year: str     # 4位
    serial: str   # 6位流水
    check: str    # 1位校验

    def __str__(self) -> str:
        return f"{self.maker}{self.kind}{self.year}{self.serial}{self.check}"

    @staticmethod
    def parse(code: str) -> "GunCode":
        if len(code) != 14:
            raise ValidationError(f"整枪码长度须为14位: {code}")
        maker, kind, year, serial, check = code[:2], code[2], code[3:7], code[7:13], code[13]
        if check != _check_digit(code[:13]):
            raise ValidationError(f"整枪码校验位错误: {code}")
        if kind not in CALIBER_KIND.values():
            raise ValidationError(f"枪种代码非法: {kind}")
        if not year.isdigit() or not serial.isdigit():
            raise ValidationError(f"年份/流水号非数字: {code}")
        return GunCode(maker, kind, year, serial, check)

    @staticmethod
    def generate(maker_name: str, kind: str, year: int, serial: int) -> "GunCode":
        if kind not in CALIBER_KIND:
            raise ValidationError(f"未知枪种: {kind}")
        if maker_name not in MAKERS:
            raise ValidationError(f"未知制造企业: {maker_name}")
        body = f"{MAKERS[maker_name]}{CALIBER_KIND[kind]}{year:04d}{serial:06d}"
        return GunCode(body[:2], body[2], body[3:7], body[7:13], _check_digit(body))


@dataclass(frozen=True)
class PartCode:
    """散件码：整枪码前缀 + 部件类别码 + 件序号（从属式）。"""

    gun_prefix: str   # 13位整枪码主体（不含校验位）
    category: str     # 2位类别
    index: int        # 件序号

    def __str__(self) -> str:
        return f"{self.gun_prefix}{self.category}{self.index:02d}"

    @staticmethod
    def generate(gun_code: str, category: str, index: int = 1) -> "PartCode":
        if category not in PART_CATEGORY:
            raise ValidationError(f"未知部件类别: {category}")
        GunCode.parse(gun_code)  # 前缀必须是合法整枪码
        return PartCode(gun_code[:13], PART_CATEGORY[category], index)

    @staticmethod
    def parse(code: str) -> "PartCode":
        if len(code) != 17:
            raise ValidationError(f"散件码长度须为17位: {code}")
        inv = {v: k for k, v in PART_CATEGORY.items()}
        cat = code[13:15]
        if cat not in inv:
            raise ValidationError(f"部件类别码非法: {code}")
        return PartCode(code[:13], cat, int(code[15:17]))


@dataclass
class GunIdentity:
    """枪支数字身份：唯一、不可变更、贯穿全生命周期。"""

    code: str
    maker: str           # 制造企业名称
    kind: str            # 枪种
    year: int
    serial: int
    legacy_no: str = ""  # 现行 GA1258 枪号（映射关系）
    parts: list[str] = field(default_factory=list)
    # 制造单位稳定 ID（赋码时固化）：档案按 ID 关联制造企业资质与生产计划，
    # 不依赖企业名称反查（名称可能改、可能与单位名不一致——评审 P2-5）
    maker_unit_id: str = ""

    def to_dict(self) -> dict:
        return {
            "code": self.code, "maker": self.maker, "kind": self.kind,
            "year": self.year, "serial": self.serial, "legacy_no": self.legacy_no,
            "parts": list(self.parts), "maker_unit_id": self.maker_unit_id,
        }

    @staticmethod
    def from_dict(d: dict) -> "GunIdentity":
        return GunIdentity(**d)
