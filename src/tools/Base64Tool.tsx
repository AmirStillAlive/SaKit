import React, { useState, useEffect } from 'react';
import {
  Lock,
  Unlock,
  Copy,
  Download,
  Trash2,
  Sparkles,
  Paperclip,
  ArrowUpDown,
  Check,
  ShieldCheck,
  Languages,
  Zap,
} from 'lucide-react';
import { Button } from '../components/ui/button';
import { Badge } from '../components/ui/badge';
import { useToast } from '../components/ui/toast';
import { cn, formatNumber, downloadText } from '../lib/utils';
import { type Lang } from '../lib/i18n';

interface Base64ToolProps {
  lang: Lang;
}

export const Base64Tool: React.FC<Base64ToolProps> = ({ lang }) => {
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [inputVal, setInputVal] = useState<string>('');
  const [outputVal, setOutputVal] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [flash, setFlash] = useState<boolean>(false);
  const { toast } = useToast();

  const isFa = lang === 'fa';

  const t = {
    title: isFa ? 'رمزگذاری / رمزگشایی Base64' : 'Base64 Encoder / Decoder',
    subtitle: isFa
      ? 'متن یا فایل را با Base64 رمزگذاری یا رمزگشایی کنید. سریع، آفلاین، امن.'
      : 'Encode text to Base64 or decode it back. Fast, offline, secure.',
    badge: isFa ? 'آفلاین • سریع • امن' : 'Offline • Fast • Secure',
    encode: isFa ? 'رمزگذاری' : 'Encode',
    decode: isFa ? 'رمزگشایی' : 'Decode',
    inputLabel: isFa ? 'ورودی' : 'Input',
    outputLabel: isFa ? 'خروجی' : 'Output',
    phEncode: isFa ? 'متن را اینجا بنویسید… مثلاً: سلام دنیا' : 'Type text here… e.g. Hello World',
    phDecode: isFa ? 'کد Base64 را اینجا وارد کنید… مثلاً: SGVsbG8=' : 'Paste Base64 here… e.g. SGVsbG8=',
    file: isFa ? 'فایل' : 'File',
    sample: isFa ? 'نمونه' : 'Sample',
    clear: isFa ? 'پاک کردن' : 'Clear',
    swap: isFa ? 'جابه‌جایی ورودی و خروجی' : 'Swap Input & Output',
    copy: isFa ? 'کپی' : 'Copy',
    download: isFa ? 'دانلود' : 'Download',
    chars: isFa ? 'کاراکتر' : 'chars',
    invalid: isFa
      ? 'ورودی Base64 معتبر نیست. کاراکترهای مجاز: A-Z a-z 0-9 + / ='
      : 'Invalid Base64 input. Allowed characters: A-Z a-z 0-9 + / =',
    copied: isFa ? 'در کلیپ‌بورد کپی شد' : 'Copied to clipboard',
    downloaded: isFa ? 'فایل دانلود شد' : 'File downloaded',
    cleared: isFa ? 'پاک شد' : 'Cleared',
    empty: isFa ? 'متنی برای کپی یا دانلود وجود ندارد' : 'Nothing to copy or download',
    sampleText: isFa ? 'سلام دنیا! Hello World' : 'Hello World! سلام دنیا',
    h1Title: isFa ? 'کاملاً آفلاین' : 'Fully Offline',
    h1Desc: isFa
      ? 'همه‌چیز در مرورگر شما پردازش می‌شود. هیچ متنی به سرور ارسال نخواهد شد.'
      : 'Everything runs directly in your browser. Nothing is uploaded.',
    h2Title: isFa ? 'پشتیبانی کامل UTF-8' : 'Real UTF-8 Support',
    h2Desc: isFa
      ? 'حفظ کامل متن‌های فارسی، خطوط چندزبانه، علائم نگارشی و کاراکترهای خاص بدون خطا.'
      : 'Preserves Persian, Arabic, special Unicode characters and formatting perfectly.',
    h3Title: isFa ? 'آنی و نامحدود' : 'Instant & Unlimited',
    h3Desc: isFa
      ? 'بدون نیاز به ثبت‌نام یا محدودیت حجم، همراه با قابلیت دانلود و کپی سریع.'
      : 'No sign-up or size limitations, with one-click copy and download.',
  };

  function utf8Encode(str: string): string {
    const bytes = new TextEncoder().encode(str);
    let bin = '';
    const len = bytes.length;
    const CHUNK_SZ = 0x8000;
    for (let i = 0; i < len; i += CHUNK_SZ) {
      bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK_SZ));
    }
    return btoa(bin);
  }

  function utf8Decode(b64: string): string {
    const clean = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (clean.length % 4)) % 4;
    const padded = clean + '='.repeat(padLen);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(padded)) {
      throw new Error('invalid');
    }
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  }

  useEffect(() => {
    if (!inputVal) {
      setOutputVal('');
      setErrorMsg('');
      return;
    }
    try {
      const res = mode === 'encode' ? utf8Encode(inputVal) : utf8Decode(inputVal);
      setOutputVal(res);
      setErrorMsg('');
      setFlash(true);
      const timer = setTimeout(() => setFlash(false), 300);
      return () => clearTimeout(timer);
    } catch {
      setOutputVal('');
      setErrorMsg(t.invalid);
    }
  }, [inputVal, mode]);

  const handleSwap = () => {
    const prevIn = inputVal;
    setInputVal(outputVal);
    setOutputVal(prevIn);
    setMode(mode === 'encode' ? 'decode' : 'encode');
  };

  const handleClear = () => {
    setInputVal('');
    setOutputVal('');
    setErrorMsg('');
    toast(t.cleared, 'info');
  };

  const handleSample = () => {
    if (mode === 'encode') {
      setInputVal(t.sampleText);
    } else {
      setInputVal(utf8Encode(t.sampleText));
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f) return;
    const r = new FileReader();
    r.onload = () => {
      const dataUrl = String(r.result || '');
      const b64 = dataUrl.split(',')[1] || '';
      setInputVal(b64);
      setMode('decode');
    };
    r.readAsDataURL(f);
    e.target.value = '';
  };

  const handleCopy = () => {
    if (!outputVal) {
      toast(t.empty, 'error');
      return;
    }
    navigator.clipboard.writeText(outputVal);
    toast(t.copied, 'success');
  };

  const handleDownload = () => {
    if (!outputVal) {
      toast(t.empty, 'error');
      return;
    }
    const filename = mode === 'encode' ? 'base64-encoded.txt' : 'base64-decoded.txt';
    downloadText(filename, outputVal);
    toast(t.downloaded, 'success');
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 animate-in fade-in duration-300">
      {/* Hero Section */}
      <div className="text-center space-y-3">
        <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-foreground">
          {t.title}
        </h1>
        <p className="text-sm sm:text-base text-muted-foreground max-w-xl mx-auto leading-relaxed">
          {t.subtitle}
        </p>
      </div>

      {/* Main Tool Card */}
      <div className="bg-card border border-border rounded-surface p-4 sm:p-6 shadow-surface space-y-5">
        {/* Mode Selector Segment */}
        <div className="flex items-center justify-between pb-3 border-b border-border">
          <div className="relative inline-flex p-1 bg-secondary/80 rounded-control border border-border">
            <span
              className={cn(
                'absolute top-1 bottom-1 w-[calc(50%-4px)] rounded-sm bg-brand/15 border border-brand/30 transition-all duration-250 ease-out shadow-[0_0_12px_rgba(0,229,127,0.2)]',
                mode === 'encode' ? 'start-1' : 'start-[calc(50%+2px)]'
              )}
              aria-hidden="true"
            />
            <button
              type="button"
              onClick={() => setMode('encode')}
              className={cn(
                'relative z-10 flex items-center gap-2 px-4 py-1.5 rounded-sm text-sm font-semibold transition-colors duration-200',
                mode === 'encode'
                  ? 'text-brand'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <Lock className="w-4 h-4 text-brand" />
              <span>{t.encode}</span>
            </button>
            <button
              type="button"
              onClick={() => setMode('decode')}
              className={cn(
                'relative z-10 flex items-center gap-2 px-4 py-1.5 rounded-sm text-sm font-semibold transition-colors duration-200',
                mode === 'decode'
                  ? 'text-brand'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <Unlock className="w-4 h-4 text-brand" />
              <span>{t.decode}</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-secondary/60 hover:bg-secondary rounded-control transition-colors border border-border/50">
              <Paperclip className="w-3.5 h-3.5" />
              <span>{t.file}</span>
              <input type="file" onChange={handleFileUpload} className="hidden" />
            </label>
            <button
              type="button"
              onClick={handleSample}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-secondary/60 hover:bg-secondary rounded-control transition-colors border border-border/50"
            >
              <Sparkles className="w-3.5 h-3.5 text-warning" />
              <span>{t.sample}</span>
            </button>
            <button
              type="button"
              onClick={handleClear}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-destructive bg-secondary/60 hover:bg-secondary rounded-control transition-colors border border-border/50"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{t.clear}</span>
            </button>
          </div>
        </div>

        {/* Input Pane */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">{t.inputLabel}</span>
            <span>
              {formatNumber(inputVal.length, lang)} {t.chars}
            </span>
          </div>
          <textarea
            value={inputVal}
            onChange={(e) => setInputVal(e.target.value)}
            rows={5}
            dir="auto"
            placeholder={mode === 'encode' ? t.phEncode : t.phDecode}
            className="w-full bg-field border border-input rounded-field p-3.5 font-mono text-sm text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-brand resize-y leading-relaxed"
            spellCheck={false}
          />
        </div>

        {/* Divider with Swap Button */}
        <div className="relative flex items-center justify-center my-3">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-border" />
          </div>
          <button
            type="button"
            onClick={handleSwap}
            title={t.swap}
            aria-label={t.swap}
            className="group relative z-10 w-10 h-10 rounded-full bg-card border border-brand/40 hover:border-brand flex items-center justify-center text-brand hover:text-brand bg-brand/5 hover:bg-brand/15 transition-all duration-300 shadow-[0_0_15px_rgba(0,229,127,0.2)] hover:shadow-[0_0_25px_rgba(0,229,127,0.45)] active:scale-90"
          >
            <ArrowUpDown className="w-4 h-4 transition-transform duration-300 group-hover:rotate-180" />
          </button>
        </div>

        {/* Error Notification */}
        {errorMsg && (
          <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-control text-destructive text-xs font-medium animate-in fade-in">
            {errorMsg}
          </div>
        )}

        {/* Output Pane */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">{t.outputLabel}</span>
            <span>
              {formatNumber(outputVal.length, lang)} {t.chars}
            </span>
          </div>
          <textarea
            value={outputVal}
            readOnly
            rows={5}
            dir="ltr"
            placeholder="Result…"
            className={cn(
              'w-full bg-field/60 border border-input/60 rounded-field p-3.5 font-mono text-sm text-foreground focus:outline-none resize-y leading-relaxed transition-colors',
              flash && 'bg-brand/10 border-brand/40'
            )}
            spellCheck={false}
          />
        </div>

        {/* Action Buttons */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleDownload}
            disabled={!outputVal}
            className="gap-2"
          >
            <Download className="w-4 h-4" />
            <span>{t.download}</span>
          </Button>
          <Button
            variant="brand"
            size="sm"
            onClick={handleCopy}
            disabled={!outputVal}
            className="gap-2"
          >
            <Copy className="w-4 h-4" />
            <span>{t.copy}</span>
          </Button>
        </div>
      </div>

      {/* Feature Hints Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
        <div className="p-4 rounded-surface bg-card/60 border border-border/70 flex gap-3.5 items-start">
          <div className="p-2 rounded-control bg-brand/10 text-brand shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-bold text-foreground">{t.h1Title}</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">{t.h1Desc}</p>
          </div>
        </div>

        <div className="p-4 rounded-surface bg-card/60 border border-border/70 flex gap-3.5 items-start">
          <div className="p-2 rounded-control bg-brand/10 text-brand shrink-0">
            <Languages className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-bold text-foreground">{t.h2Title}</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">{t.h2Desc}</p>
          </div>
        </div>

        <div className="p-4 rounded-surface bg-card/60 border border-border/70 flex gap-3.5 items-start">
          <div className="p-2 rounded-control bg-brand/10 text-brand shrink-0">
            <Zap className="w-5 h-5" />
          </div>
          <div className="space-y-1">
            <h4 className="text-sm font-bold text-foreground">{t.h3Title}</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">{t.h3Desc}</p>
          </div>
        </div>
      </div>
    </div>
  );
};
