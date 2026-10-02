"""تابع gen2_sub7dc0 — پورت ماشینی از Pantegnos (پروانه MIT).

منبع: internal/modules/impl/npvs_gen2_wb.go :: npvGen2Sub7DC0
تبدیل با tools/gen2_sub7dc0_emit.py انجام شده؛ دستی ویرایش نکنید.
"""

from __future__ import annotations


def gen2_sub7dc0(block: bytes, i: int, x3: int, x4: int, x5: int, x6: int) -> bytes:
    _m32 = lambda v: v & 0xFFFFFFFF
    _at = lambda addr: block[addr]

    out = bytearray(4)
    x0 = x8 = x9 = x10 = x11 = x12 = x13 = x14 = x15 = x16 = x17 = 0

    x2 = i
    x3, x4, x5, x6 = _m32(x3), _m32(x4), _m32(x5), _m32(x6)

    x8 = _m32(x2 + _m32(x2<<1))
    x12 = _m32(x3 >> 0x14)
    x11 = _m32(x3 >> 0x18)
    x13 = (x4 >> 0x18) & 0xf
    x14 = _m32(x5 >> 0x18)
    x10 = x6
    x9 = _m32(x8 << 3)
    x8 = x4
    x12 &= 0xf0
    x12 += x13
    x13 = _m32(x5 >> 0x14)
    x16 = x8 >> 0x1c
    x9 &= 0xFFFFFFFF
    x11 &= 0xf0
    x14 &= 0xf0
    x15 = _m32(x6>>0x18) & 0xf
    x13 &= 0xf0
    x17 = _m32(x3 >> 0x10)
    x9 <<= 8
    x8 &= 0xf
    x13 += x15
    x17 &= 0xf0
    x11 = x9 + x11
    x14 = x9 + x14
    x12 = x9 + x12
    x16 = _at(x11 + x16)
    x14 += x10 >> 28
    x12 = _at(x12 + 0x200)
    x13 = x9 + x13
    x0 = _m32(x6>>0x14) & 0xf
    x14 = _at(x14 + 0x100)
    x15 = x9 + (x16 << 4)
    x13 = _at(x13 + 0x300)
    x12 = x9 + (x12 << 4)
    x16 = _m32(x4>>0x14) & 0xf
    x10 &= 0xf
    x14 = x15 + x14
    x15 = _m32(x5 >> 0x10)
    x12 += x13
    x13 = _m32(x3 >> 0xc)
    x14 = _at(x14 + 0x400)
    x12 = _at(x12 + 0x500)
    x15 &= 0xf0
    x16 = x17 + x16
    x15 += x0
    x0 = _m32(x4>>0x10) & 0xf
    x17 = _m32(x5 >> 0xc)
    x12 |= x14 << 4
    x13 &= 0xf0
    x14 = _m32(x6>>0x10) & 0xf
    x13 += x0
    x17 &= 0xf0
    x16 = x9 + x16
    out[0] = ((x12) & 0xFF)
    x13 = x9 + x13
    x12 = x17 + x14
    x14 = _at(x16 + 0x600)
    x13 = _at(x13 + 0x800)
    x15 = x9 + x15
    x12 = x9 + x12
    x15 = _at(x15 + 0x700)
    x16 = _m32(x5 >> 8)
    x12 = _at(x12 + 0x900)
    x14 = x9 + (x14 << 4)
    x13 = x9 + (x13 << 4)
    x0 = _m32(x6>>0xc) & 0xf
    x17 = _m32(x3 >> 8)
    x14 += x15
    x12 = x13 + x12
    x13 = x16 & 0xf0
    x14 = _at(x14 + 0xa00)
    x12 = _at(x12 + 0xb00)
    x15 = _m32(x3 >> 4)
    x13 += x0
    x0 = _m32(x4>>8) & 0xf
    x16 = _m32(x4>>0xc) & 0xf
    x12 |= x14 << 4
    x14 = x15 & 0xf0
    x17 &= 0xf0
    x14 += x0
    x15 = x9 + 0xc00
    x0 = _m32(x5 >> 4)
    x17 = x15 + x17
    out[1] = ((x12) & 0xFF)
    x12 = _m32(x6>>8) & 0xf
    x16 = _at(x17 + x16)
    x14 = x9 + x14
    x17 = x0 & 0xf0
    x14 = _at(x14 + 0xe00)
    x12 = x17 + x12
    x13 = x15 + x13
    x12 = x9 + x12
    x13 = _at(x13 + 0x100)
    x15 = x9 + (x16 << 4)
    x12 = _at(x12 + 0xf00)
    x14 = x9 + (x14 << 4)
    x16 = 0x1000
    x13 = x15 + x13
    x17 = _m32(x6>>4) & 0xf
    x0 = x5 & 0xf0
    x12 = x14 + x12
    x14 = 0x1100
    x13 = _at(x13 + x16)
    x12 = _at(x12 + x14)
    x14 = 0x1200
    x15 = _m32(x4>>4) & 0xf
    x16 = x3 & 0xf0
    x17 = x0 + x17
    x14 = x9 + x14
    x12 |= x13 << 4
    x13 = (x3 & 0xf) << 4
    x16 = x14 + x16
    out[2] = ((x12) & 0xFF)
    x8 = x13 + x8
    x12 = x14 + x17
    x14 = (x5 & 0xf) << 4
    x13 = _at(x16 + x15)
    x8 = x9 + x8
    x15 = 0x1400
    x12 = _at(x12 + 0x100)
    x8 = _at(x8 + x15)
    x10 = x14 + x10
    x14 = 0x1500
    x10 = x9 + x10
    x13 = x9 + (x13 << 4)
    x10 = _at(x10 + x14)
    x8 = x9 + (x8 << 4)
    x9 = x13 + x12
    x12 = 0x1600
    x8 += x10
    x10 = 0x1700
    x9 = _at(x9 + x12)
    x8 = _at(x8 + x10)
    x8 |= x9 << 4
    out[3] = ((x8) & 0xFF)
    return bytes(out)
