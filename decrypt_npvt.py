#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
decrypt_npvt.py: دیکریپت فایل‌های کانفیگ NPV Tunnel / NapsternetV با پسوند .npvt

فرمت:   NPVT1\n<base64>,<base64>,<base64>
الگوریتم: White-Box AES-128 در حالت CTR
          - ۱۶ بایت اول هر بلاک base64 شده = nonce/IV
          - بقیه = ciphertext و با XOR کردن کی‌استریمِ تولیدشده توسط
            جدول‌های white-box باز می‌شود (بدون نیاز به کلید اصلی)

جدول‌ها (tyBoxes / mbl / xorTable / tboxesLast) از سورس Go ابزار Pantegnos
(https://github.com/FrontierTM/Pantegnos، پروانه MIT) استخراج شده‌اند.

استفاده:
    python decrypt_npvt.py <پوشه ورودی> [پوشه خروجی]
"""

import base64
import json
import os
import sys

# ---------------------------------------------------------------- جدول‌ها
_HERE = os.path.dirname(os.path.abspath(__file__))
_TABLES_PATH = os.path.join(_HERE, "npv_tables.json")

_T = json.load(open(_TABLES_PATH))
TY = _T["tyBoxes"]["data"]        # [16][256] uint32
MBL = _T["mbl"]["data"]           # [16][256] uint32
XT = _T["xorTable"]["data"]       # [96][16][16] byte
TBL = _T["tboxesLast"]["data"]    # [16][256] byte

SHIFT_ORDER = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
NR = 2  # تعداد راند (rounds) طبق سورس اصلی

_XT = XT  # shortcut


def _core(block):
    """هستهٔ رمز: یک بلاک ۱۶ بایتی را با جدول‌های white-box تبدیل می‌کند."""
    buf = list(block)

    # ShiftRows اول
    buf = [buf[SHIFT_ORDER[i]] for i in range(16)]

    # حلقهٔ بیرونی Go: for range (nr-1) → فقط یک بار؛ داخل آن: for i11 := range 4
    for i11 in range(4):
        i13 = i11 * 4
        i14, i15, i16 = i13 + 1, i13 + 2, i13 + 3

        iC = TY[i13 * 256 + buf[i13]]
        iC2 = TY[i14 * 256 + buf[i14]]
        iC3 = TY[i15 * 256 + buf[i15]]
        iC4 = TY[i16 * 256 + buf[i16]]

        # --- تبدیل اول (tyBoxes → mix با xorTable) ---
        for i17 in range(4):
            i18 = (i11 * 24) + (i17 * 6)
            i19 = i17 * 8
            i20 = 28 - i19
            i22 = 24 - i19

            n1 = (iC >> i20) & 15
            n2 = (iC2 >> i20) & 15
            n3 = (iC3 >> i20) & 15
            n4 = (iC4 >> i20) & 15
            b10 = _XT[(i18 * 16 + n1) * 16 + n2]
            b11 = _XT[(i18 * 16 + n3) * 16 + n4]

            m1 = (iC >> i22) & 15
            m2 = (iC2 >> i22) & 15
            m3 = (iC3 >> i22) & 15
            m4 = (iC4 >> i22) & 15
            lo = _XT[(i18 + 5) * 256 + _XT[(i18 + 2) * 256 + m1 * 16 + m2] * 16
                     + _XT[(i18 + 3) * 256 + m3 * 16 + m4]]
            hi = _XT[(i18 + 4) * 256 + b10 * 16 + b11]

            buf[i13 + i17] = lo | (hi << 4)

        # --- تبدیل دوم (mbl → mix با xorTable) ---
        iC5 = MBL[i13 * 256 + buf[i13]]
        iC6 = MBL[i14 * 256 + buf[i14]]
        iC7 = MBL[i15 * 256 + buf[i15]]
        iC8 = MBL[i16 * 256 + buf[i16]]

        for i27 in range(4):
            i28 = (i11 * 24) + (i27 * 6)
            i29 = i27 * 8
            i30 = 28 - i29
            i31 = 24 - i29

            n1 = (iC5 >> i30) & 15
            n2 = (iC6 >> i30) & 15
            n3 = (iC7 >> i30) & 15
            n4 = (iC8 >> i30) & 15
            a1 = _XT[(i28 * 16 + n1) * 16 + n2]
            a2 = _XT[(i28 * 16 + n3) * 16 + n4]
            hi = _XT[(i28 + 4) * 256 + a1 * 16 + a2]

            m1 = (iC5 >> i31) & 15
            m2 = (iC6 >> i31) & 15
            m3 = (iC7 >> i31) & 15
            m4 = (iC8 >> i31) & 15
            b1 = _XT[(i28 + 2) * 256 + m1 * 16 + m2]
            b2 = _XT[(i28 + 3) * 256 + m3 * 16 + m4]
            lo = _XT[(i28 + 5) * 256 + b1 * 16 + b2]

            buf[i13 + i27] = (hi << 4) | lo

    # ShiftRows آخر + لایهٔ خروجی
    buf = [buf[SHIFT_ORDER[i]] for i in range(16)]
    return bytes(TBL[i * 256 + buf[i]] for i in range(16))


def _ctr(nonce, data):
    """AES-CTR با هستهٔ white-box: counter از نوع big-endian روی ۱۶ بایت."""
    counter = list(nonce)
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        ks = _core(counter)
        for i in range(15, -1, -1):
            counter[i] = (counter[i] + 1) & 0xFF
            if counter[i]:
                break
        block = data[off:off + 16]
        for i, b in enumerate(block):
            out[off + i] = b ^ ks[i]
    return bytes(out)


def _b64(s):
    s = "".join(s.split())
    if not s:
        return b""
    s += "=" * ((-len(s)) % 4)
    return base64.b64decode(s)


def decrypt_blob(data):
    """یک بلاک base64-شده را دیکریپت می‌کند (nonce 16 بایتی ابتدای بلاک)."""
    if len(data) < 16:
        return b""
    if len(data) == 16:
        return b""
    return _ctr(data[:16], data[16:])


def decrypt_file(path):
    """همهٔ بلاک‌های یک فایل .npvt را دیکریپت کرده و لیست plaintext برمی‌گرداند."""
    raw = open(path, "rb").read().decode("utf-8", "replace")
    out = []
    for tok in raw.replace("NPVTSUB1", ",").replace("NPVT1", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            blob = _b64(tok)
        except Exception:
            continue
        if len(blob) < 32:
            continue
        pt = decrypt_blob(blob)
        if pt:
            out.append(pt)
    return out


def pretty(pt):
    """تلاش برای JSON-کردن خروجی جهت خوانایی بهتر."""
    try:
        obj = json.loads(pt.decode("utf-8", "replace"))
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return pt.decode("utf-8", "replace")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    src = argv[1]
    dst = argv[2] if len(argv) > 2 else os.path.join(src, "decrypted")

    files = []
    if os.path.isdir(src):
        for name in sorted(os.listdir(src)):
            if name.lower().endswith((".npvt", ".npv")):
                files.append(os.path.join(src, name))
    else:
        files = [src]

    os.makedirs(dst, exist_ok=True)
    ok = fail = 0
    for f in files:
        if not f.lower().endswith(".npvt"):
            print(f"[SKIP] {os.path.basename(f)} (فایل .npv رد شد)")
            continue
        try:
            parts = decrypt_file(f)
        except Exception as e:
            print(f"[FAIL] {os.path.basename(f)}: {e}")
            fail += 1
            continue
        if not parts:
            print(f"[EMPTY] {os.path.basename(f)}")
            fail += 1
            continue
        out_name = os.path.splitext(os.path.basename(f))[0] + ".txt"
        out_path = os.path.join(dst, out_name)
        with open(out_path, "w", encoding="utf-8") as fh:
            for i, p in enumerate(parts):
                fh.write(f"===== blob #{i} =====\n")
                fh.write(pretty(p))
                fh.write("\n\n")
        ok += 1
        total = sum(len(p) for p in parts)
        print(f"[OK]   {os.path.basename(f)} -> {out_name}  ({len(parts)} بلاک، {total} بایت)")
    print(f"\nنتیجه: {ok} موفق، {fail} ناموفق. خروجی در: {dst}")
    return 0 if ok else 1


if __name__ == "__main__":
    from fa_console import utf8_console

    utf8_console()
    sys.exit(main(sys.argv))
