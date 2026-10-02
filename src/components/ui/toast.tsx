import * as React from 'react';
import { Check, Info, AlertCircle, X } from 'lucide-react';
import { cn } from '../../lib/utils';

export interface ToastMessage {
  id: string;
  type?: 'success' | 'info' | 'error';
  message: string;
}

interface ToastContextType {
  toast: (message: string, type?: 'success' | 'info' | 'error') => void;
}

const ToastContext = React.createContext<ToastContextType | null>(null);

export function useToast() {
  const ctx = React.useContext(ToastContext);
  if (!ctx) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return ctx;
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ToastMessage[]>([]);

  const toast = React.useCallback((message: string, type: 'success' | 'info' | 'error' = 'success') => {
    const id = Math.random().toString(36).slice(2, 9);
    setToasts((prev) => [...prev, { id, type, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }, []);

  const dismiss = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
      {/* Toast notifications container */}
      {toasts.length > 0 && (
        <div
          role="region"
          aria-label="اعلان‌ها"
          className="fixed bottom-6 start-1/2 -translate-x-1/2 z-50 flex flex-col items-center gap-2 pointer-events-none"
        >
          {toasts.map((t) => (
            <div
              key={t.id}
              role="status"
              aria-live="polite"
              className={cn(
                'pointer-events-auto flex items-center gap-2.5 rounded-xl border px-4 py-2.5 text-xs font-medium shadow-2xl backdrop-blur-md transition-all duration-200 animate-in fade-in slide-in-from-bottom-2',
                t.type === 'success' && 'border-success/30 bg-card/95 text-foreground shadow-success/5',
                t.type === 'error' && 'border-destructive/30 bg-card/95 text-destructive shadow-destructive/5',
                t.type === 'info' && 'border-border/60 bg-card/95 text-foreground',
              )}
            >
              {t.type === 'success' && (
                <span className="flex size-5 items-center justify-center rounded-full bg-success/15 text-success">
                  <Check className="size-3.5 stroke-[2.5]" />
                </span>
              )}
              {t.type === 'error' && (
                <span className="flex size-5 items-center justify-center rounded-full bg-destructive/15 text-destructive">
                  <AlertCircle className="size-3.5 stroke-[2.5]" />
                </span>
              )}
              {t.type === 'info' && (
                <span className="flex size-5 items-center justify-center rounded-full bg-muted text-muted-foreground">
                  <Info className="size-3.5" />
                </span>
              )}
              <span>{t.message}</span>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
                aria-label="بستن اعلان"
                className="ms-1 rounded-sm text-muted-foreground hover:text-foreground cursor-pointer transition-colors"
              >
                <X className="size-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </ToastContext.Provider>
  );
}
