'use client';
import * as React from 'react';
import { Eye, EyeOff } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface PasswordInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  /** برچسب بالای فیلد. */
  label?: string;
  /** توضیح کوچک زیر فیلد. */
  hint?: React.ReactNode;
}

/**
 * ورودی رمز عبور کانفیگ: همیشه چپ‌چین (کاراکترها به ترتیب تایپ دیده می‌شوند)،
 * با دکمهٔ نمایش/پنهان‌کردن و aria-pressed.
 */
export function PasswordInput({ label, hint, className, ...props }: PasswordInputProps) {
  const [show, setShow] = React.useState(false);

  return (
    <div className="space-y-2">
      {label && (
        <label htmlFor={props.id} className="block text-xs font-medium text-muted-foreground">
          {label}
        </label>
      )}
      <div
        dir="ltr"
        className={cn(
          'flex h-10 items-center gap-1 rounded-field border border-input bg-background ps-3 pe-1 transition-colors duration-(--motion) ease-motion',
          'focus-within:ring-2 focus-within:ring-ring/60',
          className,
        )}
      >
        <input
          type={show ? 'text' : 'password'}
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          className="h-full min-w-0 flex-1 bg-transparent text-base outline-none placeholder:text-muted-foreground/70 sm:text-sm"
          {...props}
        />
        <button
          type="button"
          aria-label={show ? 'پنهان کردن رمز' : 'نمایش رمز'}
          aria-pressed={show}
          onClick={() => setShow((s) => !s)}
          className="flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-field text-muted-foreground transition-colors duration-(--motion) ease-motion hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none"
        >
          {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
        </button>
      </div>
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
