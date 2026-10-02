/**
 * General helper utilities: class name merging, Persian digit formatting,
 * file size formatting, and client-side file downloads.
 */

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** Converts ASCII digits to Persian digits for localized presentation */
export function fa(n: number | string): string {
  return String(n).replace(/[0-9]/g, (d) => '۰۱۲۳۴۵۶۷۸۹'[Number(d)]);
}

/** Formats a number with thousands separators and Persian digits */
export function faNumber(n: number): string {
  return fa(n.toLocaleString('en-US').replace(/,/g, '٬'));
}

/** Formats byte sizes with Persian units */
export function faFileSize(bytes: number): string {
  if (bytes < 1024) return `${fa(bytes)} بایت`;
  if (bytes < 1024 * 1024) return `${fa((bytes / 1024).toFixed(1))} کیلوبایت`;
  return `${fa((bytes / (1024 * 1024)).toFixed(1))} مگابایت`;
}

/** Formats number according to selected language */
export function formatNumber(n: number | string, lang: 'fa' | 'en' = 'fa'): string {
  if (lang === 'fa') return fa(n);
  return String(n);
}

/** Formats file size according to selected language */
export function formatFileSize(bytes: number, lang: 'fa' | 'en' = 'fa'): string {
  if (lang === 'fa') return faFileSize(bytes);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Triggers a client-side file download from text content */
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
