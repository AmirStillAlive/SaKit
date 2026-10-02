/** ابزارهای کمکی فارسی: cn، اعداد فارسی و حجم فایل. */

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** عدد لاتین به ارقام فارسی (برای لایه نمایش) */
export function fa(n: number | string): string {
  return String(n).replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);
}

/** جداکنندهٔ هزارگان فارسی + ارقام فارسی */
export function faNumber(n: number): string {
  return fa(n.toLocaleString('en-US').replace(/,/g, '٬'));
}

/** حجم فایل با واحد فارسی: «۱۲ کیلوبایت» */
export function faFileSize(bytes: number): string {
  if (bytes < 1024) return `${fa(bytes)} بایت`;
  if (bytes < 1024 * 1024) return `${fa((bytes / 1024).toFixed(1))} کیلوبایت`;
  return `${fa((bytes / (1024 * 1024)).toFixed(1))} مگابایت`;
}

/** قالب‌بندی عدد بسته به زبان */
export function formatNumber(n: number | string, lang: 'fa' | 'en' = 'fa'): string {
  if (lang === 'fa') return fa(n);
  return String(n);
}

/** حجم فایل سازگار با دوزبانه */
export function formatFileSize(bytes: number, lang: 'fa' | 'en' = 'fa'): string {
  if (lang === 'fa') return faFileSize(bytes);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** دانلود متن به‌صورت فایل؛ مقاوم در برابر popup-blockerها. */
export function downloadText(filename: string, content: string): void {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
