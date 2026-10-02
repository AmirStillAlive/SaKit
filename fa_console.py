#!/usr/bin/env python3
"""متن فارسی روی کنسول ویندوز.

بدون این کار، وقتی خروجی به لوله یا فایل هدایت می‌شود پایتون کنسول را با
cp1252 باز می‌کند و اولین کاراکتر فارسی `UnicodeEncodeError` می‌دهد.
فقط اسکریپت‌های اجرایی این را صدا می‌زنند؛ کتابخانه‌ها نه.
"""

from __future__ import annotations

import sys


def utf8_console() -> None:
    """stdout/stderr را روی UTF-8 می‌برد؛ اگر شد نشد، سکوت می‌کند."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
