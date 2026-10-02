import React, { useState, useEffect } from 'react';
import {
  Binary,
  ShieldCheck,
  Languages,
  Github,
  PanelLeftClose,
  PanelLeft,
  Menu,
  X,
  Lock,
  ExternalLink,
  Code2,
} from 'lucide-react';
import { Button } from './components/ui/button';
import { ToastProvider } from './components/ui/toast';
import { Base64Tool } from './tools/Base64Tool';
import { NpvTool } from './tools/NpvTool';
import { type Lang } from './lib/i18n';
import { cn } from './lib/utils';

export type ToolId = 'base64' | 'npv';

interface ToolConfig {
  id: ToolId;
  name: Record<Lang, string>;
  description: Record<Lang, string>;
  icon: React.ElementType;
  badge?: Record<Lang, string>;
}

export const TOOLS: ToolConfig[] = [
  {
    id: 'base64',
    name: {
      fa: 'Base64 Encoder / Decoder',
      en: 'Base64 Encoder / Decoder',
    },
    description: {
      fa: 'رمزگذاری و رمزگشایی متن و فایل با UTF-8',
      en: 'Encode and decode text or files with UTF-8',
    },
    icon: Binary,
  },
  {
    id: 'npv',
    name: {
      fa: 'رمزگشایی کانفیگ NPV',
      en: 'NPV Config Decryptor',
    },
    description: {
      fa: 'باز کردن فایل‌های .npvt و .npvs نسخه ۱ و ۵',
      en: 'Decrypt .npvt and .npvs (v1 & v5) configs',
    },
    icon: Lock,
    badge: {
      fa: 'v1 & v5',
      en: 'v1 & v5',
    },
  },
];

export default function App() {
  return (
    <ToastProvider>
      <AppShell />
    </ToastProvider>
  );
}

function parseCurrentRoute(): ToolId {
  const path = window.location.pathname.toLowerCase();
  const hash = window.location.hash.toLowerCase();

  // پشتیبانی همزمان از Path Routing و Hash Routing به عنوان Fallback
  if (path.includes('/npv') || hash.includes('npv')) return 'npv';
  if (path.includes('/base64') || hash.includes('base64')) return 'base64';
  return 'base64';
}

function AppShell() {
  const [lang, setLang] = useState<Lang>(() => {
    try {
      const saved = localStorage.getItem('sakit-lang');
      return saved === 'en' ? 'en' : 'fa';
    } catch {
      return 'fa';
    }
  });

  const [activeTool, setActiveTool] = useState<ToolId>(() => parseCurrentRoute());
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState<boolean>(false);

  useEffect(() => {
    try {
      localStorage.setItem('sakit-lang', lang);
    } catch {}
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
  }, [lang]);

  // مدیریت URL در تغییر ابزار و گوش دادن به popstate
  useEffect(() => {
    const handlePopState = () => {
      setActiveTool(parseCurrentRoute());
    };
    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  const navigateTo = (toolId: ToolId) => {
    setActiveTool(toolId);
    setMobileMenuOpen(false);

    // تشکیل آدرس تمیز SPA
    const base = import.meta.env.BASE_URL.replace(/\/$/, '');
    const targetUrl = `${base}/${toolId}`;
    try {
      window.history.pushState(null, '', targetUrl);
    } catch {
      window.location.hash = `/${toolId}`;
    }
  };

  const isFa = lang === 'fa';

  const t = {
    brand: 'SaKit',
    toolkit: isFa ? 'جعبه‌ابزار وب' : 'Web Toolkit',
    toolsHeading: isFa ? 'ابزارها' : 'Tools',
    langLabel: isFa ? 'EN' : 'فا',
    langTitle: isFa ? 'تغییر زبان به انگلیسی / Switch to English' : 'Switch to Persian / تغییر زبان به فارسی',
    github: isFa ? 'گیت‌هاب' : 'GitHub',
    footerText: isFa
      ? 'جعبه‌ابزار SaKit — پردازش کاملاً امن و ۱۰۰٪ آفلاین در مرورگر شما بدون ارسال داده.'
      : 'SaKit — 100% Client-Side & Offline Web Toolkit. Zero data transmission.',
    collapseSidebar: isFa ? 'بستن سایدبار' : 'Collapse sidebar',
    expandSidebar: isFa ? 'باز کردن سایدبار' : 'Expand sidebar',
  };

  return (
    <div className="relative min-h-screen flex flex-col bg-background text-foreground selection:bg-brand/20 selection:text-brand">
      {/* Dynamic Cyberpunk Ambient Background (VibeFarsi Neon Grid & Orbs) */}
      <div className="bg-fx" aria-hidden="true">
        <div className="bg-grid" />
        <div className="bg-glow" />
        <div className="bg-orb orb-a" />
        <div className="bg-orb orb-b" />
        <div className="bg-scanlines" />
      </div>

      {/* Top Navbar */}
      <header className="sticky top-0 z-30 flex items-center justify-between px-4 sm:px-6 h-14 border-b border-border bg-card/80 backdrop-blur-md">
        <div className="flex items-center gap-3">
          {/* Mobile Menu Trigger */}
          <button
            type="button"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-control text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors"
            aria-label="Toggle menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>

          {/* Desktop Sidebar Toggle */}
          <button
            type="button"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="hidden md:flex p-2 rounded-control text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors"
            title={sidebarOpen ? t.collapseSidebar : t.expandSidebar}
          >
            {sidebarOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeft className="w-4 h-4" />}
          </button>

          {/* Brand Logo */}
          <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => navigateTo('base64')}>
            <div className="w-8 h-8 rounded-lg bg-brand/10 border border-brand/30 flex items-center justify-center text-brand shadow-sm">
              <Code2 className="w-4 h-4" />
            </div>
            <div className="flex flex-col">
              <span className="font-extrabold text-base tracking-tight leading-none text-foreground flex items-center gap-1">
                SaKit<span className="text-brand">.</span>
              </span>
              <span className="text-[10px] text-muted-foreground font-medium leading-tight">
                {t.toolkit}
              </span>
            </div>
          </div>
        </div>

        {/* Top Navbar Actions */}
        <div className="flex items-center gap-2">
          {/* Language Toggle */}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setLang((prev) => (prev === 'fa' ? 'en' : 'fa'))}
            className="h-8 gap-1.5 px-3 text-xs font-medium cursor-pointer transition-all duration-200 hover:border-foreground/30 active:scale-95"
            aria-label={t.langTitle}
            title={t.langTitle}
          >
            <Languages className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="font-semibold">{t.langLabel}</span>
          </Button>
        </div>
      </header>

      {/* Main Body with Responsive Sidebar */}
      <div className="flex-1 flex overflow-hidden">
        {/* Desktop Collapsible Sidebar */}
        <aside
          className={cn(
            'hidden md:flex flex-col border-r-line border-border bg-card/50 transition-all duration-200 shrink-0 select-none',
            sidebarOpen ? 'w-64 p-3' : 'w-16 p-2 items-center'
          )}
        >
          {sidebarOpen && (
            <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
              {t.toolsHeading}
            </div>
          )}

          <nav className="flex flex-col gap-1 w-full">
            {TOOLS.map((tool) => {
              const Icon = tool.icon;
              const isActive = activeTool === tool.id;

              return (
                <button
                  key={tool.id}
                  type="button"
                  onClick={() => navigateTo(tool.id)}
                  className={cn(
                    'flex items-center rounded-control transition-all cursor-pointer text-start',
                    sidebarOpen ? 'gap-3 px-3 py-2.5 w-full' : 'p-2.5 justify-center w-full',
                    isActive
                      ? 'bg-brand/10 text-brand border border-brand/25 font-semibold shadow-xs'
                      : 'text-muted-foreground hover:text-foreground hover:bg-secondary/70 border border-transparent'
                  )}
                  title={!sidebarOpen ? tool.name[lang] : undefined}
                >
                  <Icon className={cn('shrink-0 w-4 h-4', isActive ? 'text-brand' : 'text-muted-foreground')} />
                  {sidebarOpen && (
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between gap-1">
                        <span className="text-xs truncate">{tool.name[lang]}</span>
                        {tool.badge && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-secondary text-muted-foreground border border-border">
                            {tool.badge[lang]}
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-muted-foreground/80 truncate font-normal">
                        {tool.description[lang]}
                      </p>
                    </div>
                  )}
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Mobile Slide-over Drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden fixed inset-0 z-40 flex">
            <div
              className="fixed inset-0 bg-background/80 backdrop-blur-sm"
              onClick={() => setMobileMenuOpen(false)}
            />
            <div className="relative w-4/5 max-w-xs bg-card border-r border-border p-4 flex flex-col gap-4 shadow-xl z-50">
              <div className="flex items-center justify-between pb-3 border-b border-border">
                <span className="font-bold text-sm text-foreground">{t.toolsHeading}</span>
                <button
                  type="button"
                  onClick={() => setMobileMenuOpen(false)}
                  className="p-1 rounded-control text-muted-foreground hover:text-foreground"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <nav className="flex flex-col gap-1.5">
                {TOOLS.map((tool) => {
                  const Icon = tool.icon;
                  const isActive = activeTool === tool.id;

                  return (
                    <button
                      key={tool.id}
                      type="button"
                      onClick={() => navigateTo(tool.id)}
                      className={cn(
                        'flex items-center gap-3 p-3 rounded-control transition-all cursor-pointer text-start w-full',
                        isActive
                          ? 'bg-brand/10 text-brand border border-brand/25 font-semibold'
                          : 'text-muted-foreground hover:text-foreground hover:bg-secondary/70 border border-transparent'
                      )}
                    >
                      <Icon className={cn('shrink-0 w-5 h-5', isActive ? 'text-brand' : 'text-muted-foreground')} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-1">
                          <span className="text-sm">{tool.name[lang]}</span>
                          {tool.badge && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-secondary text-muted-foreground border border-border">
                              {tool.badge[lang]}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground font-normal">
                          {tool.description[lang]}
                        </p>
                      </div>
                    </button>
                  );
                })}
              </nav>
            </div>
          </div>
        )}

        {/* Active Tool Content Area */}
        <main className="flex-1 overflow-y-auto px-4 sm:px-8 py-8">
          <div className="max-w-4xl mx-auto">
            {activeTool === 'base64' && <Base64Tool lang={lang} />}
            {activeTool === 'npv' && <NpvTool lang={lang} />}
          </div>
        </main>
      </div>

      {/* Global Footer */}
      <footer className="border-t border-border bg-card/40 px-4 sm:px-8 py-4 text-xs text-muted-foreground flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="text-center sm:text-start leading-relaxed">
          {t.footerText}
        </p>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/AmirStillAlive/SaKit"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1 underline underline-offset-4 hover:text-foreground"
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub</span>
          </a>
        </div>
      </footer>
    </div>
  );
}
