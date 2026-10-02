export type Lang = 'fa' | 'en';

export interface FAQItem {
  id: string;
  title: string;
  content: string;
}

export const FAQ_DATA: Record<Lang, FAQItem[]> = {
  fa: [
    {
      id: 'how',
      title: 'چطور کار می‌کند؟',
      content:
        'فایل npvt در واقع چند رشته base64 است که با AES-128 در حالت CTR رمز شده و کلید آن به شکل جدول‌های عمومی white-box پیاده شده است. این صفحه با استفاده از جدول‌های ریاضیاتی متن‌باز (پورت‌شده از پروژه آزاد Pantegnos)، کی‌استریم را کاملاً داخل مرورگر شما می‌سازد و نیازی به کلید مخفی سرور نیست. فایل‌های npvs نسخهٔ ۱ و ۵ نیز با جدول‌های عمومی gen1 و gen2 و رمزنگاری ChaCha20-Poly1305 کاملاً آفلاین باز می‌شوند. هیچ کدی مستقیماً از هیچ اپلیکیشن انحصاری استخراج نشده است.',
    },
    {
      id: 'npvs-pass',
      title: 'چه فایل‌هایی نیاز به رمز دارند؟',
      content:
        'فایل‌های npvs نسخهٔ ۱ و نسخهٔ ۵ که توسط سازنده قفل شده‌اند، با PBKDF2 محافظت می‌شوند و برای باز شدن نیاز به رمز عبور تعیین‌شده توسط سازنده دارند. با وارد کردن رمز عبور در کادر بالا، قفل آن‌ها باز می‌شود. فایل‌هایی که فقط برای یک شناسه سخت‌افزاری یا کلید خصوصی خاص ساخته شده باشند با این روش باز نمی‌شوند.',
    },
    {
      id: 'safe',
      title: 'این رمز امن است؟',
      content:
        'نه. چون جدول‌های رمز عمومی و در پروژه‌های متن‌باز شناخته‌شده هستند، هر کسی می‌تواند همین کار را بکند و این ساختار فقط جلوی خوانده شدن مستقیم را می‌گیرد. نکته مهم‌تر این است که کانفیگی که از این فایل‌ها بیرون می‌آید به سرور سازنده همان کانفیگ وصل می‌شود، پس حتما بدانید به چه سروری اعتماد می‌کنید.',
    },
    {
      id: 'privacy',
      title: 'فایل من کجا می‌رود؟',
      content:
        'فایل فقط داخل همین صفحه خوانده می‌شود و هیچ درخواستی به هیچ سروری فرستاده نمی‌شود. وب‌اپلیکیشن مجهز به Service Worker و پشتیبانی PWA است؛ با یک بار باز شدن صفحه، تمام فایل‌ها، اسکریپت‌ها و جدول‌ها در حافظهٔ مرورگر (Cache Storage) ذخیره می‌شوند و بعد از آن حتی با قطعی کامل اینترنت، صفحه و فرآیند رمزگشایی کاملاً آفلاین کار می‌کنند.',
    },
    {
      id: 'batch',
      title: 'آیا می‌توانم چند فایل را همزمان رمزگشایی کنم؟',
      content:
        'بله؛ می‌توانید چندین فایل .npvt و .npvs را همزمان انتخاب کرده یا در کادر رها کنید تا همه یکجا رمزگشایی شوند. پس از استخراج، با نوار جست‌وجو یا فیلترهای پروتکل می‌توانید بین آن‌ها بگردید یا با دکمه‌های «کپی همه» و «دانلود لینک‌ها» تمام کانفیگ‌ها را یکجا دریافت کنید.',
    },
    {
      id: 'clients',
      title: 'کانفیگ‌های استخراج‌شده در چه برنامه‌هایی کار می‌کنند؟',
      content:
        'لینک‌های استاندارد خروجی (شامل VLESS با TLS یا Reality، VMess، Trojan، Shadowsocks و پروکسی‌های HTTP و SOCKS5) مستقیماً در نرم‌افزارهای V2rayNG، NikaNG، v2rayN، Sing-box، Streisand، FoXray، Nekoray و Hiddify قابل استفاده هستند. همچنین فایل کامل JSON هر کانفیگ برای کلاینت‌های پیشرفته قابل دانلود است.',
    },
  ],
  en: [
    {
      id: 'how',
      title: 'How does it work?',
      content:
        'An .npvt file consists of base64-encoded strings encrypted with AES-128 in CTR mode using public white-box key tables. This web page embeds those open-source tables (ported from the open-source Pantegnos project) and generates the keystream locally in your browser without requiring any secret key from a server. Version 1 and Version 5 .npvs files are also supported: decrypted offline using public gen1 & gen2 white-box tables and ChaCha20-Poly1305. No proprietary assets were extracted from any closed-source APK.',
    },
    {
      id: 'npvs-pass',
      title: 'Which files require a password?',
      content:
        'NPVS v1 and v5 files locked by their creator use PBKDF2 password derivation and require the creator’s password. Entering the password in the field above decrypts the payload. Files tied strictly to a specific hardware device ID or private key cannot be opened with this method.',
    },
    {
      id: 'safe',
      title: 'Is this encryption secure?',
      content:
        'No. Because white-box tables are mathematically public and documented in open-source research, anyone can decrypt these files. Furthermore, the extracted configs route traffic through the creator’s server, so only connect to servers you trust.',
    },
    {
      id: 'privacy',
      title: 'Where do my files go?',
      content:
        'All processing is performed 100% locally in your browser. No files, configs, or queries are ever sent to any remote server. The web app is a Progressive Web App (PWA) with a Service Worker that caches all scripts, styles, and tables, enabling it to load and decrypt files completely offline without an active internet connection.',
    },
    {
      id: 'batch',
      title: 'Can I decrypt multiple files simultaneously?',
      content:
        'Yes. You can drag and drop or select multiple .npvt and .npvs files at once. All configs will be extracted in a single batch, and you can search, filter by protocol, copy all links, or download them together.',
    },
    {
      id: 'clients',
      title: 'Which VPN apps can use the exported configs?',
      content:
        'The generated client links (including VLESS with TLS/Reality, VMess, Trojan, Shadowsocks, and HTTP/SOCKS5 proxies) work directly in V2rayNG, v2rayN, NikaNG, Sing-box, Streisand, FoXray, Nekoray, and Hiddify. Full JSON configurations can also be downloaded for advanced client setups.',
    },
  ],
};

export const I18N = {
  fa: {
    langLabel: 'EN',
    langTitle: 'تغییر زبان به انگلیسی / Switch to English',
    badge: 'کاملاً آفلاین در مرورگر شما: بدون ارسال فایل به هیچ سرور',
    title: 'رمزگشایی کانفیگ NPV Tunnel',
    subtitle:
      'فایل کانفیگ .npvt یا .npvs نسخهٔ ۱ و ۵ را بگذارید تا به JSON خوانا و لینک آمادهٔ ورود تبدیل شود. رمزگشایی با جدول‌های white-box کاملاً داخل همین صفحه اجرا می‌شود.',
    uploadDropHint: 'فایل‌های .npvt یا .npvs را این‌جا رها کنید یا',
    uploadBrowse: 'انتخاب کنید',
    uploadHintDefault: 'امکان انتخاب و رمزگشایی همزمان چند فایل .npvt یا .npvs',
    uploadClearAll: 'پاک کردن همه',
    btnDecrypt: 'رمزگشایی کن',
    btnDecryptMultiple: (count: number) => `رمزگشایی کن (${count} فایل)`,
    btnDecrypting: 'در حال رمزگشایی…',
    btnLoadingTables: 'بارگذاری جدول‌های رمز…',
    passAlertTitle: 'این فایل دارای رمز عبور است',
    passSingleFile: (name: string) => `فایل «${name}» دارای رمز عبور است. لطفاً رمز را وارد کنید.`,
    passMultiFiles: (names: string[]) => `فایل‌های «${names.join('»، «')}» دارای رمز عبور هستند. لطفاً رمز را وارد کنید.`,
    passLabel: 'رمز عبور کانفیگ',
    passPlaceholder: 'رمز عبور را وارد کنید',
    passHint: 'رمز را سازندهٔ کانفیگ تعیین کرده است.',
    passConfirm: 'تأیید و رمزگشایی',
    searchPlaceholder: 'جست‌وجو در نام، سرور، پروتکل یا لینک…',
    tabAll: 'همه',
    tabAllWithCount: (count: number) => `همه (${count})`,
    downloadAllLinks: 'دانلود همه لینک‌ها',
    copyVisibleLinks: 'کپی لینک‌های فیلترشده',
    downloadRawJson: 'دانلود JSON خام',
    downloadJson: 'دانلود JSON',
    showFullJson: 'نمایش ساختار کامل JSON کانفیگ',
    noLinkReady: 'لینک آماده برای این نوع پروتکل ساخته نشد. خروجی JSON را ببینید.',
    copyLink: 'کپی',
    copied: 'کپی شد',
    clearFilters: 'پاک کردن فیلترها',
    emptySearchTitle: 'هیچ کانفیگی مطابق با فیلتر شما یافت نشد',
    emptySearchDesc: 'عبارت جست‌وجو یا تب فیلتر را تغییر دهید یا دکمه زیر را بزنید تا تمام کانفیگ‌ها نمایش داده شوند.',
    faqTitle: 'راهنما و پرسش‌های پرتکرار',
    footerOpenSource: 'متن‌باز با پروانه MIT و جدول‌های پروژه Pantegnos',
    githubRepo: 'مخزن گیت‌هاب',
    toastAllCopied: (count: number) => `${count} لینک در کلیپ‌بورد کپی شد`,
    toastLinkCopied: (proto: string) => `لینک ${proto.toUpperCase()} در کلیپ‌بورد کپی شد`,
    toastJsonDownloaded: (name: string) => `JSON کانفیگ «${name}» دانلود شد`,
  },
  en: {
    langLabel: 'فا',
    langTitle: 'تغییر زبان به فارسی / Switch to Persian',
    badge: 'Runs 100% offline in your browser: no files sent to any server',
    title: 'NPV Tunnel Config Decryptor',
    subtitle:
      'Drop your .npvt or .npvs (v1 & v5) config files to get readable JSON and ready-to-use client links. Decrypted locally using white-box tables.',
    uploadDropHint: 'Drop .npvt or .npvs files here or',
    uploadBrowse: 'browse files',
    uploadHintDefault: 'Supports batch decryption of multiple .npvt or .npvs files',
    uploadClearAll: 'Clear all',
    btnDecrypt: 'Decrypt',
    btnDecryptMultiple: (count: number) => `Decrypt (${count} files)`,
    btnDecrypting: 'Decrypting…',
    btnLoadingTables: 'Loading cipher tables…',
    passAlertTitle: 'Password-Protected File',
    passSingleFile: (name: string) => `File "${name}" is password protected. Please enter the password.`,
    passMultiFiles: (names: string[]) => `Files "${names.join('", "')}" are password protected. Please enter the password.`,
    passLabel: 'Config Password',
    passPlaceholder: 'Enter config password',
    passHint: 'Password was set by the config creator.',
    passConfirm: 'Decrypt',
    searchPlaceholder: 'Search by name, server, protocol, or link…',
    tabAll: 'All',
    tabAllWithCount: (count: number) => `All (${count})`,
    downloadAllLinks: 'Download all links',
    copyVisibleLinks: 'Copy filtered links',
    downloadRawJson: 'Download raw JSON',
    downloadJson: 'Download JSON',
    showFullJson: 'Show full config JSON structure',
    noLinkReady: 'Direct client link not available for this protocol. See JSON output.',
    copyLink: 'Copy',
    copied: 'Copied',
    clearFilters: 'Clear filters',
    emptySearchTitle: 'No configs found matching your filter',
    emptySearchDesc: 'Adjust your search query or protocol filter, or click below to reset and view all configs.',
    faqTitle: 'Frequently Asked Questions & Guide',
    footerOpenSource: 'Open-source under MIT license · Tables from Pantegnos project',
    githubRepo: 'GitHub Repository',
    toastAllCopied: (count: number) => `${count} links copied to clipboard`,
    toastLinkCopied: (proto: string) => `${proto.toUpperCase()} link copied to clipboard`,
    toastJsonDownloaded: (name: string) => `JSON config for "${name}" downloaded`,
  },
} as const;
