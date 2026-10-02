#!/usr/bin/env python3
"""پشتیبانی نسخهٔ ۵ (.npvs نسل جدید، پاکت فشرده gen2) — بخش ۱: ثابت‌ها و A16.

پورت پایتون از پروژهٔ Pantegnos (پروانه MIT):
    internal/modules/impl/npvs_gen2.go
    internal/modules/impl/npvs_gen2_wb.go
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import zlib
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from gen2_sub7dc0 import gen2_sub7dc0

from npvs import (  # همان پیاده‌سازی v1؛ رمزنگاری مشترک است
    _chacha20poly1305_open,
    _decode_sentinels,
    _pbkdf2_sha256,
    NeedsPassphrase,
    NpvsError,
)

ENVELOPE_VERSION = 5
HEADER_FIXED = 135
META_AAD_LEN = 131
METADATA_INFO = b"NPVS-v5/metadata"
FIELD_KEY_INFO = b"NPV-fields-v1/field/"
RECORD_AAD_INFO = b"NPV-fields-v1/record/"
BODY_MAGIC = b"NPF\x01"
KEY_BLOCK_OFFSET = 53
SENTINEL_SEQ = 0xFFFF
METHOD_RECIPIENT = 0
METHOD_PASS = 1
METHOD_APPKEY = 2
RECIPIENT_PK_SIZE = 32
RECIPIENT_WRAP_SIZE = 0x5D
PASS_BLOCK_SIZE = 80
APPKEY_BLOCK_SIZE = 78
KEY_SIZE = 32
SIG_SIZE = 64
MIN_ITERS = 1
MAX_ITERS = 10_000_000

GEN2_BLOCK_SIZE = 57344
GEN2_BLOCK_COUNT = 13
GEN2_PAGE_SIZE = 4096
GEN2_TABLES_SIZE = GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE + GEN2_PAGE_SIZE
GEN2_APPKEY_LABEL = b"npvtunnel/appkey/v2 "
GEN2_SHIFT_ROWS = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)

_TABLES_PATH = Path(__file__).with_name("npvs_gen2_tables.bin.z")
_TABLES: bytes | None = None


class Gen2Error(Exception):
    """خطا در باز کردن پاکت نسل ۲."""


class NeedsGen2Passphrase(Gen2Error):
    """این فایل نسل ۲ با رمز عبور محافظت شده است."""

    def __init__(self, message: str, creator_message: str = "") -> None:
        super().__init__(message)
        self.creator_message = creator_message


def load_gen2_tables() -> bytes:
    global _TABLES
    if _TABLES is not None:
        return _TABLES
    try:
        raw_z = _TABLES_PATH.read_bytes()
    except OSError as exc:
        raise Gen2Error(f"جدول‌های gen2 پیدا نشد: {_TABLES_PATH.name}") from exc
    try:
        tables = zlib.decompress(raw_z)
    except zlib.error as exc:
        raise Gen2Error(f"جدول‌های gen2 خراب است: {exc}") from exc
    if len(tables) != GEN2_TABLES_SIZE:
        raise Gen2Error(
            f"جدول‌های gen2 باید {GEN2_TABLES_SIZE} بایت باشند، نه {len(tables)}"
        )
    _TABLES = tables
    return tables


def _be32(block: bytes, off: int) -> int:
    return int.from_bytes(block[off : off + 4], "big")


def _group_args(block: bytes, half: int, j: int, s: bytes) -> tuple[int, int, int, int]:
    base = half + 0x1000 * j
    return (
        _be32(block, base + 4 * s[0]),
        _be32(block, base + 0x400 + 4 * s[1]),
        _be32(block, base + 0x800 + 4 * s[2]),
        _be32(block, base + 0xC00 + 4 * s[3]),
    )


def _shift(state: bytearray) -> None:
    t = bytes(state[i] for i in GEN2_SHIFT_ROWS)
    state[:] = t


def _group(state: bytearray, block: bytes, j: int) -> None:
    # توجه: برش bytearray در پایتون کپی است؛ باید صریحا در state بنویسیم
    args = _group_args(block, 0x6000, j, bytes(state[4 * j : 4 * j + 4]))
    state[4 * j : 4 * j + 4] = gen2_sub7dc0(block, j, *args)
    args = _group_args(block, 0xA000, j, bytes(state[4 * j : 4 * j + 4]))
    state[4 * j : 4 * j + 4] = gen2_sub7dc0(block, j, *args)


def gen2_a16(salt: bytes) -> bytes:
    """خروجی ۱۶ بایتی white-box نسل ۲ از روی نمک."""
    if len(salt) != 16:
        raise Gen2Error(f"نمک gen2 باید ۱۶ بایت باشد، نه {len(salt)}")
    tables = load_gen2_tables()
    state = bytearray(salt)
    for b in range(GEN2_BLOCK_COUNT):
        block = tables[b * GEN2_BLOCK_SIZE : (b + 1) * GEN2_BLOCK_SIZE]
        _shift(state)
        for j in range(4):
            _group(state, block, j)
    page = tables[GEN2_BLOCK_COUNT * GEN2_BLOCK_SIZE :]
    return bytes(page[0x100 * i + state[GEN2_SHIFT_ROWS[i]]] for i in range(16))


def gen2_kdk(a16: bytes, config_id: bytes) -> bytes:
    """KDK نسل ۲: SHA-256 روی (label + a16 + configID)."""
    h = hashlib.sha256()
    h.update(GEN2_APPKEY_LABEL)
    h.update(a16)
    h.update(config_id)
    return h.digest()


# ---------------------------------------------------------------------------
# تجزیهٔ پاکت فشردهٔ v5
# ---------------------------------------------------------------------------


def is_gen2_envelope(data: bytes) -> bool:
    return len(data) >= 9 and data[:4] == b"NPVS" and data[4] == ENVELOPE_VERSION


def parse_gen2_envelope(data: bytes) -> dict:
    """پاکت فشردهٔ v5 را می‌شکافد (آفست‌ها عینا از Go)."""
    if not is_gen2_envelope(data):
        raise Gen2Error("پاکت فشردهٔ v5 نیست")

    hdr_len = int.from_bytes(data[5:9], "big")
    if hdr_len < HEADER_FIXED or 9 + hdr_len > len(data):
        raise Gen2Error(f"طول سرآیند نامعتبر: {hdr_len}")
    h = data[9 : 9 + hdr_len]
    if h[0] != 1:
        raise Gen2Error(f"نسخهٔ سرآیند فشرده پشتیبانی نمی‌شود: {h[0]}")

    env: dict[str, Any] = {
        "header": h,
        "config_id": h[1:17],
        "creator": h[17:50],
        "method": h[50],
    }
    method = env["method"]
    if method not in (METHOD_RECIPIENT, METHOD_PASS, METHOD_APPKEY):
        raise Gen2Error(f"روش باز کردن ناشناخته: {method}")

    recipients = int.from_bytes(h[51:53], "big")
    if recipients > 0x400:
        raise Gen2Error(f"تعداد گیرنده خیلی زیاد است: {recipients}")
    if method == METHOD_RECIPIENT and recipients == 0:
        raise Gen2Error("سرآیند پاکت فشرده نامعتبر است")
    env["recipients"] = recipients

    off = KEY_BLOCK_OFFSET + recipients * (RECIPIENT_PK_SIZE + RECIPIENT_WRAP_SIZE)
    if method == METHOD_PASS:
        if off + PASS_BLOCK_SIZE + 4 > len(h):
            raise Gen2Error("بلوک passphrase بریده شده است")
        env["iters"] = int.from_bytes(h[off : off + 4], "big")
        if not MIN_ITERS <= env["iters"] <= MAX_ITERS:
            raise Gen2Error(f"تعداد تکرار نامعتبر: {env['iters']}")
        env["salt"] = h[off + 4 : off + 20]
        env["wrap"] = h[off + 20 : off + PASS_BLOCK_SIZE]
        off += PASS_BLOCK_SIZE
    elif method == METHOD_APPKEY:
        if off + APPKEY_BLOCK_SIZE + 4 > len(h):
            raise Gen2Error("بلوک appKey بریده شده است")
        if int.from_bytes(h[off : off + 2], "big") != METHOD_APPKEY:
            raise Gen2Error("بلوک appKey پیدا نشد")
        env["salt"] = h[off + 2 : off + 18]
        env["wrap"] = h[off + 18 : off + APPKEY_BLOCK_SIZE]
        off += APPKEY_BLOCK_SIZE

    if off + 4 > len(h):
        raise Gen2Error("طول متاباب مهرشده بریده شده است")
    meta_len = int.from_bytes(h[off : off + 4], "big")
    if meta_len < 16 or off + 4 + meta_len > len(h):
        raise Gen2Error(f"طول متاباب مهرشده نامعتبر: {meta_len}")
    env["prefix"] = h[:off]
    env["meta_blob"] = h[off + 4 : off + 4 + meta_len]

    off = 9 + hdr_len
    if off + 16 > len(data):
        raise Gen2Error("سرآیند بدنه بریده شده است")
    env["nonce"] = data[off : off + 12]
    body_len = int.from_bytes(data[off + 12 : off + 16], "big")
    off += 16
    if body_len < 32 or off + body_len + SIG_SIZE > len(data):
        raise Gen2Error(f"طول بدنه نامعتبر: {body_len}")
    env["body"] = data[off : off + body_len]
    env["sig"] = data[off + body_len : off + body_len + SIG_SIZE]
    return env


def parse_gen2_body(body: bytes) -> tuple[bytes, list[tuple[int, int, bytes]]]:
    """بدنهٔ NPF را می‌خواند: contentID + فهرست (seq, flags, blob)."""
    if len(body) < 66 or body[:4] != BODY_MAGIC:
        raise Gen2Error("بدنهٔ NPF نامعتبر است")
    content_id = body[4:36]
    count = int.from_bytes(body[36:38], "big")
    off = 38
    rows: list[tuple[int, int, bytes]] = []
    for _ in range(count):
        if off + 6 > len(body):
            raise Gen2Error("سربرگ فیلد NPF بریده شده است")
        seq = int.from_bytes(body[off : off + 2], "big")
        flags = int.from_bytes(body[off + 2 : off + 4], "big")
        blob_len = int.from_bytes(body[off + 4 : off + 6], "big")
        if off + 6 + blob_len > len(body):
            raise Gen2Error("blo بستهٔ فیلد NPF بریده شده است")
        rows.append((seq, flags, body[off + 6 : off + 6 + blob_len]))
        off += 6 + blob_len
    return content_id, rows


# ---------------------------------------------------------------------------
# باز کردن کلید و محتوا
# ---------------------------------------------------------------------------


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, out_len: int = 32) -> bytes:
    if not salt:
        salt = bytes(out_len)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = bytearray()
    prev = b""
    counter = 1
    while len(out) < out_len:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        out += prev
        counter += 1
    return bytes(out[:out_len])


def gen2_open(env: dict, password: str = "") -> tuple[bytes, dict, list[tuple[str, str]]]:
    """پاکت را باز می‌کند: (DEK، متابابِ خوانا، فهرست کلیدها)."""
    method = env["method"]

    if method == METHOD_APPKEY:
        a16 = gen2_a16(env["salt"])
        kdk = gen2_kdk(a16, env["config_id"])
        method_keys = [("appKey A16 (gen-2 whitebox)", a16.hex())]
    elif method == METHOD_PASS:
        if not password:
            raise NeedsGen2Passphrase(
                "برای باز کردن این فایل نسل ۵ به رمز عبور نیاز است"
            )
        kdk = _pbkdf2_sha256(
            password.encode("utf-8"), env["salt"], env["iters"], 32
        )
        method_keys = [
            ("kdf", f"pbkdf2-hmac-sha256 iterations={env['iters']}"),
        ]
    else:
        raise Gen2Error(
            f"روش باز کردن {method} به کلید خصوصی گیرنده نیاز دارد"
        )

    # wrap: nonce(12) || ct+tag؛ AAD = نمک
    dek = _chacha20poly1305_open(kdk, env["wrap"][:12], env["wrap"][12:], env["salt"])
    if dek is None:
        if method == METHOD_PASS:
            raise NeedsGen2Passphrase("رمز عبور درست نیست")
        raise Gen2Error("باز کردن پاکت کلید ناموفق بود")

    # متاباب: ChaCha با AAD = prefix (همهٔ بایت‌های سرآیند قبل از طول متاباب)
    meta_key = _hkdf_sha256(dek, env["nonce"], METADATA_INFO)
    metadata = _chacha20poly1305_open(
        meta_key, env["nonce"], env["meta_blob"], env["prefix"]
    )
    if metadata is None:
        raise Gen2Error("متاباب مهرشده باز نشد")

    keys: list[tuple[str, str]] = [
        ("configId", env["config_id"].hex()),
        ("creator.pk", env["creator"].hex()),
    ]
    keys.extend(method_keys)
    keys.append(("KDK", kdk.hex()))
    keys.append(("DEK/CEK", dek.hex()))
    return dek, {"metadata": metadata}, keys


def _decrypt_fields(env: dict, dek: bytes) -> dict[int, bytes]:
    """فیلدهای NPF را یکی‌یکی با کلیدهای HKDF باز می‌کند."""
    content_id, rows = parse_gen2_body(env["body"])
    fields: dict[int, bytes] = {}
    for seq, _flags, blob in rows:
        pt_len = len(blob) - 16
        if pt_len < 0:
            continue
        info = FIELD_KEY_INFO + seq.to_bytes(2, "big")
        key = _hkdf_sha256(dek, content_id, info)
        aad = (
            RECORD_AAD_INFO
            + content_id
            + seq.to_bytes(2, "big")
            + pt_len.to_bytes(4, "big")
        )
        pt = _chacha20poly1305_open(key, bytes(12), blob, aad)
        if pt is not None:
            fields[seq] = pt
    return fields


def _field_text(raw: bytes) -> str:
    s = raw.decode("utf-8", errors="replace").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s[1:-1]
    return s


def gen2_configs(fields: dict[int, bytes]) -> list[dict] | None:
    """جدول sentinel (seq=۰xFFFF) را به لیست کانفیگ‌ها تبدیل می‌کند."""
    table = fields.get(SENTINEL_SEQ)
    if table is None:
        return None

    def substitute(v: Any) -> Any:
        # در Go هر عدد (float64) مرجع فیلد است؛ پایتون int و float می‌سازد
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)) and float(v) == int(v):
            return _decode_sentinels(_field_text(fields.get(int(v), b"")))
        if isinstance(v, dict):
            return {k: substitute(x) for k, x in v.items()}
        if isinstance(v, list):
            return [substitute(x) for x in v]
        return v

    spec = json.loads(table.decode("utf-8", errors="replace"))
    return [substitute(c) for c in spec.get("configs", [])]
