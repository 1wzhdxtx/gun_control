"""标识体系：整枪码 / 散件码 / 校验位。"""
import sys
sys.path.insert(0, ".")

import pytest

from gunreg.common import ValidationError
from gunreg.identity import GunCode, PartCode, CALIBER_KIND, GunIdentity


class TestGunCode:
    def test_generate_and_parse_roundtrip(self):
        code = GunCode.generate("云南西南", "手枪", 2026, 1)
        parsed = GunCode.parse(str(code))
        assert str(parsed) == str(code)
        assert parsed.serial == "000001"

    def test_check_digit_catches_mutation(self):
        code = str(GunCode.generate("云南西南", "手枪", 2026, 1))
        tampered = code[:-1] + ("0" if code[-1] != "0" else "1")
        with pytest.raises(ValidationError):
            GunCode.parse(tampered)

    def test_legacy_mapping(self):
        """整枪码与现行枪号保持可映射：legacy_no 作为独立字段关联。"""
        ident = GunIdentity(code=str(GunCode.generate("北方装备", "猎枪", 2025, 7)),
                            maker="北方装备", kind="猎枪", year=2025, serial=7,
                            legacy_no="GA1258-2025-0007")
        d = ident.to_dict()
        assert GunIdentity.from_dict(d).legacy_no == "GA1258-2025-0007"


class TestPartCode:
    def test_part_code_is_subordinate(self):
        gun = str(GunCode.generate("云南西南", "步枪", 2026, 3))
        part = str(PartCode.generate(gun, "枪管", 1))
        assert part.startswith(gun[:13])
        parsed = PartCode.parse(part)
        assert parsed.gun_prefix == gun[:13]
        assert parsed.index == 1

    def test_invalid_category(self):
        gun = str(GunCode.generate("云南西南", "步枪", 2026, 3))
        with pytest.raises(ValidationError):
            PartCode.generate(gun, "不存在部件")