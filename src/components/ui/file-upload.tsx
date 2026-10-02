'use client';

import * as React from 'react';
import { FileUp, Trash2, X } from 'lucide-react';
import { cn, fa, faFileSize, formatNumber, formatFileSize } from '../../lib/utils';

export interface FileUploadProps {
  accept?: string;
  multiple?: boolean;
  maxSize?: number;
  onFiles?: (files: File[]) => void;
  onFile?: (file: File | null) => void;
  hint?: React.ReactNode;
  className?: string;
  lang?: 'fa' | 'en';
}

/**
 * File upload component: drag-and-drop zone, multi-file selection,
 * individual removal, and batch clearing with bilingual support.
 */
export function FileUpload({
  accept,
  multiple = true,
  maxSize,
  onFiles,
  onFile,
  hint,
  className,
  lang = 'fa',
}: FileUploadProps) {
  const [files, setFiles] = React.useState<File[]>([]);
  const [over, setOver] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const inputRef = React.useRef<HTMLInputElement>(null);

  const notify = React.useCallback(
    (next: File[]) => {
      onFiles?.(next);
      onFile?.(next[0] ?? null);
    },
    [onFiles, onFile],
  );

  function add(list: FileList | null, append = false) {
    if (!list || list.length === 0) return;
    const incoming = Array.from(list);
    const tooBig = maxSize ? incoming.find((f) => f.size > maxSize) : undefined;
    if (tooBig) {
      setError(
        lang === 'en'
          ? `"${tooBig.name}" is larger than ${formatFileSize(maxSize!, 'en')}.`
          : `«${tooBig.name}» بزرگ‌تر از ${formatFileSize(maxSize!, 'fa')} است.`,
      );
      return;
    }
    setError(null);
    let next: File[];
    if (append && multiple) {
      const existingKeys = new Set(files.map((f) => `${f.name}:${f.size}`));
      const uniqueIncoming = incoming.filter((f) => !existingKeys.has(`${f.name}:${f.size}`));
      next = [...files, ...uniqueIncoming];
    } else {
      next = multiple ? incoming : incoming.slice(0, 1);
    }
    setFiles(next);
    notify(next);
  }

  function remove(index: number) {
    const next = files.filter((_, j) => j !== index);
    setFiles(next);
    notify(next);
  }

  function clearAll() {
    setFiles([]);
    notify([]);
    if (inputRef.current) inputRef.current.value = '';
  }

  const isEn = lang === 'en';

  return (
    <div className={cn('space-y-3', className)}>
      <div
        role="button"
        tabIndex={0}
        aria-label={isEn ? 'Select or drop config files' : 'انتخاب یا رها کردن فایل کانفیگ'}
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          add(e.dataTransfer.files, true);
        }}
        className={cn(
          'flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border border-dashed p-8 text-center transition-all duration-(--motion) ease-motion',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60',
          over
            ? 'border-brand/80 bg-brand/10 shadow-[0_0_25px_-5px_oklch(0.8_0.165_65/0.25)] scale-[0.995]'
            : 'border-border/80 hover:border-foreground/40 hover:bg-muted/30',
        )}
      >
        <div
          className={cn(
            'flex size-10 items-center justify-center rounded-full transition-all duration-(--motion)',
            over ? 'bg-brand/20 text-brand scale-110' : 'bg-secondary text-foreground',
          )}
        >
          <FileUp className="size-5" />
        </div>
        <p className="text-sm font-medium text-foreground">
          {isEn ? (
            <>
              Drop <span dir="ltr" className="font-semibold text-brand">.npvt</span> or{' '}
              <span dir="ltr" className="font-semibold text-brand">.npvs</span> files here, or{' '}
              <span className="text-primary underline underline-offset-4">browse</span>
            </>
          ) : (
            <>
              فایل‌های <span dir="ltr" className="font-semibold text-brand">.npvt</span> یا{' '}
              <span dir="ltr" className="font-semibold text-brand">.npvs</span> را این‌جا رها کنید یا{' '}
              <span className="text-primary underline underline-offset-4">انتخاب کنید</span>
            </>
          )}
        </p>
        <p className="text-xs text-muted-foreground">
          {hint ??
            (isEn
              ? multiple
                ? 'Supports batch decryption of multiple files'
                : 'Select a single config file'
              : multiple
                ? 'امکان انتخاب و رمزگشایی همزمان چند فایل فراهم است'
                : 'یک فایل انتخاب کنید')}
        </p>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          multiple={multiple}
          aria-label={isEn ? 'Choose .npvt or .npvs config file' : 'انتخاب فایل کانفیگ .npvt یا .npvs'}
          className="sr-only"
          onChange={(e) => {
            add(e.target.files);
            // Reset input value so selecting the same file again still fires change event
            e.target.value = '';
          }}
        />
      </div>

      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}

      {files.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center justify-between px-1 text-xs text-muted-foreground">
            <span>
              {isEn
                ? `${files.length} file${files.length > 1 ? 's' : ''} selected (total ${formatFileSize(
                    files.reduce((acc, f) => acc + f.size, 0),
                    'en',
                  )})`
                : `${fa(files.length)} فایل انتخاب‌شده (مجموعاً ${formatFileSize(
                    files.reduce((acc, f) => acc + f.size, 0),
                    'fa',
                  )})`}
            </span>
            {files.length > 1 && (
              <button
                type="button"
                onClick={clearAll}
                className="inline-flex cursor-pointer items-center gap-1 text-xs text-muted-foreground hover:text-destructive transition-colors"
              >
                <Trash2 className="size-3" />
                {isEn ? 'Clear all' : 'پاک کردن همه'}
              </button>
            )}
          </div>

          <ul className="divide-y divide-border/60 overflow-hidden rounded-lg border border-border/80 bg-card">
            {files.map((f, i) => (
              <li
                key={`${f.name}-${i}`}
                className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-xs transition-colors hover:bg-muted/15"
              >
                <span className="min-w-0 flex-1 truncate font-medium text-foreground" dir="auto" title={f.name}>
                  {f.name}
                </span>
                <span className={cn('shrink-0 font-mono text-[11px] text-muted-foreground', !isEn && 'fa-num')}>
                  {formatFileSize(f.size, lang)}
                </span>
                <button
                  type="button"
                  aria-label={isEn ? `Remove file ${f.name}` : `حذف فایل ${f.name}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    remove(i);
                  }}
                  className="flex size-6 shrink-0 cursor-pointer items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-destructive transition-colors"
                >
                  <X className="size-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
