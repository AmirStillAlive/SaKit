#!/usr/bin/env python3
"""رمزگشایی فرمت NPVS (کانفیگ NPV Tunnel / NapsternetV).

پیاده‌سازی از سورس Go پروژهٔ Pantegnos (پروانه MIT) استخراج و به پایتون پورت شده است:

    internal/modules/impl/npvs.go
    internal/modules/impl/npvs_wb.go

برخلاف .npvt، فایل NPVS یک پاکت کامل با سرآیند JSON است و محتوایش با
ChaCha20-Poly1305 محافظت می‌شود. کلید از دو راه به دست می‌آید:

  1. appKey      کلید جاسازی‌شده در اپ (white-box) -> بدون رمز، کاملا آفلاین
  2. passphrase  PBKDF2-HMAC-SHA256               -> به رمز عبور نیاز دارد

هیچ وابستگی بیرونی لازم نیست؛ ChaCha20-Poly1305 در همین فایل و PBKDF2 با
کتابخانهٔ استاندارد پیاده شده‌اند.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

__all__ = [
    "NpvsError",
    "NeedsPassphrase",
    "decrypt_npvs",
    "parse_envelope",
    "custodian_kdks",
]

# ---------------------------------------------------------------------------
# ثابت‌ها
# ---------------------------------------------------------------------------

_MAGIC = b"NPVS"
_MIN_LEN = 89
_WRAP_SIZE = 60
_SALT_SIZE = 16
_SIG_SIZE = 64
_KDF_APPKEY = "wbaes-ctr-sha256"
_KDF_PASS = "pbkdf2-hmac-sha256"
_KEYGEN = 1
_MAX_ITERS = 10_000_000

_TABLES_PATH = Path(__file__).with_name("npvs_tables.json")

# پیشوند KDF و ترتیب جابه‌جایی سطرها در هستهٔ white-box
_WB_KDF_PREFIX = b"npvtunnel/appkey/v1 "
_WB_SHIFT_ROWS = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)

# نشانه‌گذاری رشته‌های مبهم‌شده در متن باز شده
_SENTINEL_PREFIX = "npvs1:"
_SENTINEL_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)


class NpvsError(Exception):
    """خطا در باز کردن فایل NPVS."""


class NeedsPassphrase(NpvsError):
    """این فایل با رمز عبور محافظت شده و رمز در دسترس نیست."""

    def __init__(self, message: str, creator_message: str = "") -> None:
        super().__init__(message)
        self.creator_message = creator_message



# ---------------------------------------------------------------------------
# ChaCha20 (RFC 8439)
# ---------------------------------------------------------------------------

_CHACHA_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & _MASK32


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """یک بلاک ۶۴ بایتی از ChaCha20 می‌سازد."""
    state = list(_CHACHA_CONST)
    state += [int.from_bytes(key[i * 4 : i * 4 + 4], "little") for i in range(8)]
    state.append(counter & _MASK32)
    state += [int.from_bytes(nonce[i * 4 : i * 4 + 4], "little") for i in range(3)]

    x = list(state)
    for _ in range(10):  # ۲۰ دور؛ هر دور یک ستون و یک ردیف
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15)):
            x[a] = (x[a] + x[b]) & _MASK32
            x[d] = _rotl32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & _MASK32
            x[b] = _rotl32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & _MASK32
            x[d] = _rotl32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & _MASK32
            x[b] = _rotl32(x[b] ^ x[c], 7)
        for a, b, c, d in ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & _MASK32
            x[d] = _rotl32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & _MASK32
            x[b] = _rotl32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & _MASK32
            x[d] = _rotl32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & _MASK32
            x[b] = _rotl32(x[b] ^ x[c], 7)

    return b"".join(((x[i] + state[i]) & _MASK32).to_bytes(4, "little") for i in range(16))


def _chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """داده را با کی‌استریم ChaCha20 XOR می‌کند."""
    out = bytearray(len(data))
    for off in range(0, len(data), 64):
        ks = _chacha20_block(key, counter, nonce)
        chunk = data[off : off + 64]
        for j in range(len(chunk)):
            out[off + j] = chunk[j] ^ ks[j]
        counter += 1
    return bytes(out)


def _poly1305(msg: bytes, key: bytes) -> bytes:
    """Poly1305 یک‌بارمصرف."""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")

    p = (1 << 130) - 5
    acc = 0
    for off in range(0, len(msg), 16):
        block = msg[off : off + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p

    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _poly1305_input(aad: bytes, ct: bytes) -> bytes:
    """ورودی MAC طبق RFC 8439: aad || pad || ct || pad || طول‌ها."""
    mac = bytearray()
    mac += aad
    mac += b"\0" * (-len(aad) % 16)
    mac += ct
    mac += b"\0" * (-len(ct) % 16)
    mac += len(aad).to_bytes(8, "little")
    mac += len(ct).to_bytes(8, "little")
    return bytes(mac)


def _chacha20poly1305_open(
    key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes
) -> bytes | None:
    """ChaCha20-Poly1305 decrypt؛ اگر تگ نادرست باشد None برمی‌گرداند."""
    if len(nonce) != 12 or len(ct_and_tag) < 16:
        return None

    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    plain = _chacha20_xor(key, 1, nonce, ct)

    expected = _poly1305(_poly1305_input(aad, ct), otk)
    return plain if hmac.compare_digest(expected, tag) else None


def _chacha20poly1305_seal(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """ChaCha20-Poly1305 encrypt؛ فقط برای ساخت نمونهٔ آزمون."""
    otk = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, 1, nonce, plaintext)
    return ct + _poly1305(_poly1305_input(aad, ct), otk)



# ---------------------------------------------------------------------------
# هستهٔ white-box برای KDF
# ---------------------------------------------------------------------------

_TABLES: dict[str, Any] | None = None


def _load_tables() -> dict[str, Any]:
    """جدول‌های white-box را یک‌بار می‌خواند و آمادهٔ استفاده می‌کند."""
    global _TABLES
    if _TABLES is not None:
        return _TABLES

    doc = json.loads(_TABLES_PATH.read_text(encoding="utf-8"))
    tables = doc["tables"]

    def raw(key: str) -> bytes:
        return base64.b64decode(tables[key]["data"])

    def be32(key: str) -> list[list[int]]:
        data = raw(key)
        return [
            [
                int.from_bytes(data[(i * 256 + j) * 4 : (i * 256 + j) * 4 + 4], "big")
                for j in range(256)
            ]
            for i in range(16)
        ]

    def table(key: str) -> list[list[int]]:
        data = raw(key)
        return [list(data[i * 256 : (i + 1) * 256]) for i in range(16)]

    _TABLES = {
        "ty": be32("tyboxes"),
        "mbl": be32("mbl"),
        "xor": raw("xor"),
        "tlast_v1": table("tboxes_last"),
        "tlast_v2": table("tboxes_last_v2"),
    }
    return _TABLES


def _wb_xor(tab: bytes, t: int, a: int, b: int) -> int:
    return tab[(t << 8) + (a << 4) + b]


def _wb_mix(tab: bytes, grp: int, k: int, a: int, b: int, c: int, d: int) -> int:
    """یک بایت از ترکیب جدول‌ها؛ معادل wbMix در Go."""
    t = grp * 24 + k * 6
    hi = 28 - 8 * k
    lo = 24 - 8 * k
    p1 = _wb_xor(tab, t, (a >> hi) & 15, (b >> hi) & 15)
    p2 = _wb_xor(tab, t + 1, (c >> hi) & 15, (d >> hi) & 15)
    p3 = _wb_xor(tab, t + 2, (a >> lo) & 15, (b >> lo) & 15)
    p4 = _wb_xor(tab, t + 3, (c >> lo) & 15, (d >> lo) & 15)
    return (_wb_xor(tab, t + 4, p1, p2) << 4) | _wb_xor(tab, t + 5, p3, p4)


def _wb_block(block: bytes, tlast: list[list[int]]) -> bytes:
    """یک بلاک ۱۶ بایتی را با جدول‌های white-box تبدیل می‌کند."""
    t = _load_tables()
    tab = t["xor"]
    s = [block[i] for i in _WB_SHIFT_ROWS]

    for grp in range(4):
        base = grp * 4
        for name in ("ty", "mbl"):
            box = t[name]
            a = box[base + 0][s[base + 0]]
            b = box[base + 1][s[base + 1]]
            c = box[base + 2][s[base + 2]]
            d = box[base + 3][s[base + 3]]
            for k in range(4):
                s[base + k] = _wb_mix(tab, grp, k, a, b, c, d)

    s = [s[i] for i in _WB_SHIFT_ROWS]
    return bytes(tlast[i][s[i]] for i in range(16))


def _wb_ctr(nonce: bytes, data: bytes, tlast: list[list[int]]) -> bytes:
    """white-box AES-CTR؛ همان الگوی نسخهٔ .npvt ولی با جدول نهایی دیگر."""
    counter = bytearray(nonce[:16])
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        ks = _wb_block(bytes(counter), tlast)
        n = min(len(data) - off, 16)
        for j in range(n):
            out[off + j] = data[off + j] ^ ks[j]
        for p in range(15, -1, -1):
            counter[p] = (counter[p] + 1) & 0xFF
            if counter[p]:
                break
    return bytes(out)


def custodian_kdks(salt: bytes) -> list[bytes]:
    """کلیدهای مشتق‌شده از white-box برای باز کردن appKey.

    برای هر دو نسل جدول نهایی یک کلید جدا می‌سازیم؛ بعدا با ChaCha20 امتحان
    می‌کنیم کدام‌یک واقعا کلید درست است.
    """
    t = _load_tables()
    material = bytearray(32)
    material[:16] = salt[:16]

    kdks = []
    for variant in ("tlast_v1", "tlast_v2"):
        stream = _wb_ctr(bytes(material[:16]), bytes(material[16:]), t[variant])
        kdks.append(hashlib.sha256(_WB_KDF_PREFIX + stream).digest())
    return kdks



# ---------------------------------------------------------------------------
# کمک‌کارها
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    """base64 url-safe را با تحمل نبودن padding رمزگشایی می‌کند."""
    for decoder in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decoder(s + "=" * (-len(s) % 4))
        except (binascii.Error, ValueError):
            continue
    raise NpvsError("مقدار base64 نامعتبر است")


def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """PBKDF2-HMAC-SHA256.

    در Go یک نسخهٔ دست‌نویس استفاده شده، ولی آزمون خودش ثابت می‌کند که خروجی
    با نسخهٔ استاندارد یکی است؛ پس از همان استفاده می‌کنیم.
    """
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen)


# ---------------------------------------------------------------------------
# تجزیهٔ پاکت
# ---------------------------------------------------------------------------


def parse_envelope(data: bytes) -> dict[str, Any]:
    """سرآیند NPVS را می‌خواند و اجزای پاکت را برمی‌گرداند.

    چیدمان:
        "NPVS" | نسخه (۱ بایت) | طول سرآیند (۴ بایت BE) | سرآیند JSON
        | nonce (۱۲ بایت) | طول بدنه (۴ بایت BE) | بدنه | امضا (۶۴ بایت)
    """
    if len(data) < _MIN_LEN:
        raise NpvsError(f"فایل خیلی کوتاه است: {len(data)} بایت")
    if data[:4] != _MAGIC:
        raise NpvsError("امضای NPVS پیدا نشد")

    version = data[4]
    if version > 1:
        raise NpvsError(f"نسخهٔ پشتیبانی‌نشده: {version}")

    hdr_len = int.from_bytes(data[5:9], "big")
    if 9 + hdr_len > len(data):
        raise NpvsError(f"طول سرآیند نامعتبر: {hdr_len}")

    header_raw = data[9 : 9 + hdr_len]
    try:
        hdr = json.loads(header_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NpvsError(f"سرآیند JSON خوانده نشد: {exc}") from exc

    off = 9 + hdr_len
    if off + 16 > len(data):
        raise NpvsError("فایل وسط nonce یا طول بدنه بریده شده است")

    nonce = data[off : off + 12]
    body_len = int.from_bytes(data[off + 12 : off + 16], "big")
    off += 16

    if body_len < 16 or off + body_len + _SIG_SIZE > len(data):
        raise NpvsError(f"طول بدنه نامعتبر: {body_len}")

    return {
        "version": version,
        "header": hdr,
        "header_raw": header_raw,
        "nonce": nonce,
        "body": data[off : off + body_len],
        "sig": data[off + body_len : off + body_len + _SIG_SIZE],
    }


def _creator_message(hdr: dict[str, Any]) -> str:
    policy = hdr.get("policy") or {}
    parts = []
    for key in ("customServerMessage", "displayMessage"):
        value = (policy.get(key) or "").strip()
        if value:
            parts.append(value)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# باز کردن کلید
# ---------------------------------------------------------------------------


def _unwrap_app_key(wrap_obj: dict[str, Any]) -> bytes:
    """کلید را از appKey جاسازی‌شده باز می‌کند؛ رمز عبور لازم نیست."""
    kdf = wrap_obj.get("kdf")
    if kdf != _KDF_APPKEY:
        raise NpvsError(f"KDF پشتیبانی‌نشده برای appKey: {kdf!r}")
    if wrap_obj.get("keyId") != _KEYGEN:
        raise NpvsError(f"نسل کلید پیدا نشد: {wrap_obj.get('keyId')!r}")

    salt = _b64url_decode(wrap_obj["salt"])
    if len(salt) != _SALT_SIZE:
        raise NpvsError(f"نمک باید {_SALT_SIZE} بایت باشد، نه {len(salt)}")

    wrap = _b64url_decode(wrap_obj["wrap"])
    if len(wrap) != _WRAP_SIZE:
        raise NpvsError(f"پاکت کلید باید {_WRAP_SIZE} بایت باشد، نه {len(wrap)}")

    for kdk in custodian_kdks(salt):
        dek = _chacha20poly1305_open(kdk, wrap[:12], wrap[12:], salt)
        if dek is not None:
            return dek

    raise NpvsError("هیچ کلید custodian ای با این فایل نخواند")


def _unwrap_passphrase(wrap_obj: dict[str, Any], password: str) -> bytes:
    """کلید را از رمز عبور باز می‌کند."""
    kdf = wrap_obj.get("kdf")
    if kdf != _KDF_PASS:
        raise NpvsError(f"KDF پشتیبانی‌نشده برای passphrase: {kdf!r}")

    iterations = wrap_obj.get("iters")
    if not isinstance(iterations, int) or not 1 <= iterations <= _MAX_ITERS:
        raise NpvsError(f"تعداد تکرار نامعتبر: {iterations!r}")
    if not password:
        raise NpvsError("برای باز کردن این فایل به رمز عبور نیاز است")

    salt = _b64url_decode(wrap_obj["salt"])
    wrap = _b64url_decode(wrap_obj["wrap"])
    if len(wrap) != _WRAP_SIZE:
        raise NpvsError(f"پاکت کلید باید {_WRAP_SIZE} بایت باشد، نه {len(wrap)}")

    derived = _pbkdf2_sha256(password.encode("utf-8"), salt, iterations, 32)
    dek = _chacha20poly1305_open(derived, wrap[:12], wrap[12:], salt)
    if dek is None:
        raise NpvsError("رمز عبور درست نیست")
    return dek


# ---------------------------------------------------------------------------
# نشانه‌های مبهم‌شده
# ---------------------------------------------------------------------------


def _decode_sentinels(text: str) -> str:
    """رشته‌های npvs1:<base64> را به متن اصلی برمی‌گرداند."""
    out: list[str] = []
    rest = text
    while True:
        i = rest.find(_SENTINEL_PREFIX)
        if i < 0:
            out.append(rest)
            break
        out.append(rest[:i])
        rest = rest[i + len(_SENTINEL_PREFIX) :]

        j = 0
        while j < len(rest) and rest[j] in _SENTINEL_ALPHABET:
            j += 1
        token, rest = rest[:j], rest[j:]

        # توکن خالی یا نامعتبر: همان نشانه را دست‌نخورده برگردان
        if not token:
            out.append(_SENTINEL_PREFIX)
            continue

        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4))
            out.append(decoded.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            # توکن قابل تفسیر نبود؛ دست‌نخورده نگهش می‌داریم
            out.append(_SENTINEL_PREFIX + token)

    return "".join(out)


# ---------------------------------------------------------------------------
# نقطهٔ ورود
# ---------------------------------------------------------------------------


def _decrypt_npvs_gen2(data: bytes, password: str = "") -> dict[str, Any]:
    """نسخهٔ ۵ را باز می‌کند؛ import تنبل چون npvs_gen2 خودش از npvs وارد می‌کند."""
    from npvs_gen2 import (  # noqa: PLC0415
        Gen2Error,
        NeedsGen2Passphrase,
        _decrypt_fields,
        gen2_configs,
        gen2_open,
        parse_gen2_envelope,
    )

    env = parse_gen2_envelope(data)
    try:
        dek, meta, keys = gen2_open(env, password)
    except NeedsGen2Passphrase as exc:
        raise NeedsPassphrase(str(exc), exc.creator_message) from exc
    except Gen2Error as exc:
        raise NpvsError(str(exc)) from exc

    fields = _decrypt_fields(env, dek)
    configs = gen2_configs(fields)
    if configs is None:
        # جدول sentinel نیست؛ خامِ فیلدها را به‌صورت JSON برمی‌گردانیم
        configs = [
            {"seq": seq, "text": raw.decode("utf-8", errors="replace")}
            for seq, raw in sorted(fields.items())
            if seq != 0xFFFF
        ]

    try:
        metadata: Any = json.loads(meta["metadata"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        metadata = None

    policy = (metadata or {}).get("policy") or {}
    creator_message = "\n".join(
        str(policy.get(k) or "").strip()
        for k in ("customServerMessage", "displayMessage")
        if str(policy.get(k) or "").strip()
    )

    notes = [
        (
            "کلید با white-box نسل ۲ (appKey) باز شد؛ رمز عبور لازم نبود."
            if env["method"] == 2
            else "کلید با رمز عبور و PBKDF2 باز شد."
        )
    ]

    return {
        "format": "npvs",
        "plaintext": json.dumps(configs, ensure_ascii=False, indent=2),
        "json": configs,
        "meta": {
            "version": 5,
            "configId": env["config_id"].hex(),
            "issuedAt": (metadata or {}).get("issuedAt"),
            "policy": policy,
            "creatorMessage": creator_message,
            "signature": env["sig"].hex(),
        },
        "keys": keys,
        "notes": notes,
    }


def decrypt_npvs(data: bytes, password: str = "") -> dict[str, Any]:
    """فایل NPVS را باز می‌کند.

    خروجی دیکشنری است با کلیدهای plaintext، json، meta، keys و notes.
    اگر فایل با رمز محافظت شده باشد و رمز داده نشود، NeedsPassphrase پرتاب می‌شود.
    نسخهٔ ۵ (پاکت فشرده gen2) به npvs_gen2 فرستاده می‌شود.
    """
    if len(data) >= 5 and data[:4] == _MAGIC and data[4] == 5:
        return _decrypt_npvs_gen2(data, password)

    env = parse_envelope(data)
    hdr = env["header"]

    notes: list[str] = []
    keys: list[tuple[str, str]] = [
        ("configId", str(hdr.get("configId") or "")),
        ("creator.fp", str((hdr.get("creator") or {}).get("fp") or "")),
        ("creator.pk", str((hdr.get("creator") or {}).get("pk") or "")),
    ]

    app_key = hdr.get("appKey")
    passphrase = hdr.get("passphrase")

    try:
        if app_key is not None:
            dek = _unwrap_app_key(app_key)
            notes.append("کلید از appKey داخل اپ باز شد؛ رمز عبور لازم نبود.")
        elif passphrase is not None:
            dek = _unwrap_passphrase(passphrase, password)
            notes.append("کلید با رمز عبور و PBKDF2 باز شد.")
        elif hdr.get("recipients"):
            raise NpvsError(
                "این فایل برای گیرنده‌های مشخص رمز شده و به کلید خصوصی نیاز دارد."
            )
        else:
            raise NpvsError("هیچ راه باز کردنی در سرآیند پیدا نشد.")
    except NpvsError as exc:
        # اگر فایل با رمز محافظت شده باشد، پیام راهنمای دقیق‌تری می‌دهیم
        if passphrase is not None:
            raise NeedsPassphrase(str(exc), _creator_message(hdr)) from exc
        raise

    keys.append(("DEK/CEK", dek.hex()))

    # توجه: تگ ChaCha در ۱۶ بایت آخر خودِ body است. فیلد ۶۴ بایتی sig یک امضای
    # جداگانه است و اصلا به رمزگشایی محتوا ربطی ندارد.
    plaintext = _chacha20poly1305_open(dek, env["nonce"], env["body"], env["header_raw"])
    if plaintext is None:
        raise NpvsError("رمزگشایی محتوا شکست خورد؛ تگ تأیید نادرست است")

    text = _decode_sentinels(plaintext.decode("utf-8", errors="replace"))

    # اگر متن خودش JSON است، برای مصرف‌کنندهٔ وب ساختارشده هم برگردان
    try:
        parsed: Any = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    return {
        "format": "npvs",
        "plaintext": text,
        "json": parsed,
        "meta": {
            "version": env["version"],
            "configId": hdr.get("configId"),
            "issuedAt": hdr.get("issuedAt"),
            "policy": hdr.get("policy") or {},
            "creatorMessage": _creator_message(hdr),
            "signature": env["sig"].hex(),
        },
        "keys": keys,
        "notes": notes,
    }


def main(argv: list[str]) -> int:
    """خط فرمان:  python npvs.py <فایل|پوشه> [پوشه خروجی] [--password رمز]"""
    password = ""
    if "--password" in argv:
        i = argv.index("--password")
        password = argv[i + 1] if i + 1 < len(argv) else ""
        argv = argv[:i] + argv[i + 2 :]

    if not argv:
        print("استفاده: python npvs.py <پوشه یا فایل NPVS> [پوشه خروجی] [--password رمز]")
        return 2

    target = Path(argv[0])
    outdir = Path(argv[1]) if len(argv) > 1 else None

    files = sorted(target.glob("*.npvs")) if target.is_dir() else [target]
    if not files:
        print("فایل NPVS پیدا نشد")
        return 1

    failures = 0
    for path in files:
        try:
            res = decrypt_npvs(path.read_bytes(), password)
        except NpvsError as exc:
            failures += 1
            print(f"[x] {path.name}: {exc}")
            if isinstance(exc, NeedsPassphrase) and exc.creator_message:
                print(f"    پیام سازنده: {exc.creator_message}")
            continue

        print(f"[ok] {path.name}")
        for note in res["notes"]:
            print(f"    {note}")
        for name, value in res["keys"]:
            if value:
                print(f"    {name}: {value}")

        if outdir:
            outdir.mkdir(parents=True, exist_ok=True)
            dest = outdir / f"{path.stem}.txt"
            # نوشتن بایت‌محور تا در ویندوز هم \n به \r\n تبدیل نشود و هش خروجی
            # با نسخهٔ جاوااسکریپت یکی بماند
            dest.write_bytes(res["plaintext"].encode("utf-8"))
            print(f"    نوشته شد: {dest}")

    return 1 if failures else 0


if __name__ == "__main__":
    import sys

    from fa_console import utf8_console

    utf8_console()
    raise SystemExit(main(sys.argv[1:]))
