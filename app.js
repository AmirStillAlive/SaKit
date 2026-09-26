/* SaKit — Base64 Web: UTF-8 safe encode/decode + FA/EN i18n */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var input = $("input"), output = $("output"), err = $("error"), toast = $("toast");
  var inputCount = $("inputCount"), outputCount = $("outputCount");
  var tabEncode = $("tabEncode"), tabDecode = $("tabDecode");
  var mode = "encode";
  var store = {
    get: function (k) { try { return window.localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { window.localStorage.setItem(k, v); } catch (e) {} }
  };
  var lang = store.get("b64-lang") || "fa";

  var I18N = {
    fa: {
      dir: "rtl", htmlLang: "fa", langLabel: "EN",
      title: "رمزگذاری / رمزگشایی Base64",
      subtitle: "متن را با Base64 رمزگذاری یا رمزگشایی کنید. سریع، آفلاین، مینیمال.",
      github: "گیت‌هاب",
      encode: "رمزگذاری", decode: "رمزگشایی",
      inputLabel: "ورودی", outputLabel: "خروجی",
      inputPhEncode: "متن را اینجا بنویسید… مثلا: سلام دنیا",
      inputPhDecode: "کد Base64 را اینجا بنویسید… مثلا:2LPbjNiv2KfZhA==",
      file: "فایل", sample: "نمونه", clear: "پاک",
      copy: "کپی", download: "دانلود",
      pill: "آفلاین • سریع • امن", live: "زنده",
      h1t: "کاملاً آفلاین", h2t: "UTF-8 واقعی", h3t: "آنی و رایگان",
      hint3: "بدون ثبت‌نام، بدون محدودیت، با خروجی آماده کپی و دانلود.",
      hint1: "همه‌چیز در مرورگر شما انجام می‌شود. چیزی ارسال نمی‌شود.",
      hint2: "از UTF-8 پشتیبانی می‌کند: فارسی و ایموجی بدون مشکل.",
      swap: "جابه‌جایی ورودی و خروجی",
      invalid: "ورودی Base64 معتبر نیست. کاراکترهای مجاز: A–Z a–z 0–9 + / =",
      copied: "کپی شد ✓",
      copyFail: "کپی نشد. دستی انتخاب کنید.",
      downloaded: "دانلود شد ✓",
      empty: "چیزی برای دانلود نیست.",
      cleared: "پاک شد.",
      sampleText: "سلام دنیا! Hello World 👋"
    },
    en: {
      dir: "ltr", htmlLang: "en", langLabel: "فا",
      title: "Base64 Encoder / Decoder",
      subtitle: "Encode text to Base64 or decode it back. Fast, offline, minimal.",
      github: "GitHub",
      encode: "Encode", decode: "Decode",
      inputLabel: "Input", outputLabel: "Output",
      inputPhEncode: "Type text here… e.g. Hello World",
      inputPhDecode: "Paste Base64 here… e.g. SGVsbG8=",
      file: "File", sample: "Sample", clear: "Clear",
      copy: "Copy", download: "Download",
      pill: "Offline • Fast • Private", live: "Live",
      h1t: "Fully offline", h2t: "Real UTF-8", h3t: "Instant & free",
      hint3: "No sign-up, no limits, with copy-ready and downloadable output.",
      hint1: "Everything runs in your browser. Nothing is uploaded.",
      hint2: "UTF-8 safe: Persian text and emoji work fine.",
      swap: "Swap input and output",
      invalid: "Invalid Base64 input. Allowed chars: A–Z a–z 0–9 + / =",
      copied: "Copied ✓",
      copyFail: "Copy failed. Select manually.",
      downloaded: "Downloaded ✓",
      empty: "Nothing to download.",
      cleared: "Cleared.",
      sampleText: "Hello World! سلام دنیا 👋"
    }
  };

  function faDigits(s) {
    return String(s).replace(/[0-9]/g, function (d) { return "۰۱۲۳۴۵۶۷۸۹"[+d]; });
  }
  function fmtCount(n) {
    var t = n + (lang === "fa" ? " کاراکتر" : " chars");
    return lang === "fa" ? faDigits(t) : t;
  }

  function t(key) { return I18N[lang][key]; }

  function applyLang() {
    var d = I18N[lang];
    document.documentElement.lang = d.htmlLang;
    document.documentElement.dir = d.dir;
    $("langLabel").textContent = d.langLabel;
    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var k = el.getAttribute("data-i18n");
      if (d[k]) el.textContent = d[k];
    });
    input.placeholder = mode === "encode" ? d.inputPhEncode : d.inputPhDecode;
    $("swapBtn").setAttribute("aria-label", d.swap);
    render(true);
    updateCounts();
  }

  function utf8Encode(str) {
    var bytes = new TextEncoder().encode(str);
    var bin = "";
    var len = bytes.length;
    var CHUNK_SZ = 0x8000;
    for (var i = 0; i < len; i += CHUNK_SZ) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SZ));
    }
    return btoa(bin);
  }
  function utf8Decode(b64) {
    var clean = b64.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
    var padLen = (4 - (clean.length % 4)) % 4;
    clean += "=".repeat(padLen);
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) throw new Error("bad");
    var bin = atob(clean);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  }

  function showError(msg) {
    if (!msg) { err.hidden = true; err.textContent = ""; return; }
    err.hidden = false; err.textContent = msg;
  }
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.remove("toast-out");
    toast.hidden = false;
    clearTimeout(showToast._t);
    showToast._t = setTimeout(function () {
      toast.classList.add("toast-out");
      setTimeout(function () {
        toast.hidden = true;
        toast.classList.remove("toast-out");
      }, 220);
    }, 1800);
  }

  function updateCounts() {
    inputCount.textContent = fmtCount(input.value.length);
    outputCount.textContent = fmtCount(output.value.length);
    var hasOut = output.value.length > 0;
    $("copyBtn").disabled = !hasOut;
    $("downloadBtn").disabled = !hasOut;
  }

  function render(skipToast) {
    var v = input.value;
    if (!v) {
      output.value = "";
      showError("");
      updateCounts();
      return;
    }
    try {
      var res = mode === "encode" ? utf8Encode(v) : utf8Decode(v);
      if (res !== output.value) {
        output.value = res;
        output.classList.add("flash-update");
        clearTimeout(output._flashT);
        output._flashT = setTimeout(function () {
          output.classList.remove("flash-update");
        }, 320);
      }
      showError("");
    } catch (e) {
      output.value = "";
      showError(t("invalid"));
    }
    updateCounts();
  }

  function setMode(m) {
    mode = m;
    tabEncode.classList.toggle("is-active", m === "encode");
    tabDecode.classList.toggle("is-active", m === "decode");
    tabEncode.setAttribute("aria-selected", m === "encode");
    tabDecode.setAttribute("aria-selected", m === "decode");
    var ind = $("segInd");
    if (ind) ind.style.insetInlineStart = m === "decode" ? "50%" : "4px";
    input.placeholder = m === "encode" ? t("inputPhEncode") : t("inputPhDecode");
    render();
  }

  tabEncode.addEventListener("click", function () { setMode("encode"); });
  tabDecode.addEventListener("click", function () { setMode("decode"); });
  input.addEventListener("input", function () { render(); });

  $("swapBtn").addEventListener("click", function () {
    var tmp = input.value; input.value = output.value; output.value = tmp;
    setMode(mode === "encode" ? "decode" : "encode");
  });
  $("clearBtn").addEventListener("click", function () {
    input.value = ""; output.value = ""; showError(""); updateCounts(); input.focus();
    showToast(t("cleared"));
  });
  $("sampleBtn").addEventListener("click", function () {
    if (mode === "encode") input.value = t("sampleText");
    else input.value = utf8Encode(t("sampleText"));
    render();
  });

  $("fileInput").addEventListener("change", function (e) {
    var f = e.target.files && e.target.files[0];
    if (!f) return;
    var r = new FileReader();
    r.onload = function () {
      var dataUrl = String(r.result || "");
      input.value = dataUrl.split(",")[1] || "";
      setMode("decode");
    };
    r.readAsDataURL(f);
    e.target.value = "";
  });

  $("copyBtn").addEventListener("click", function () {
    var v = output.value;
    if (!v) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(v).then(
        function () { showToast(t("copied")); },
        function () { fallbackCopy(v); }
      );
    } else fallbackCopy(v);
  });
  function fallbackCopy(v) {
    output.select();
    try {
      document.execCommand("copy");
      showToast(t("copied"));
    } catch (e) { showToast(t("copyFail")); }
  }

  $("downloadBtn").addEventListener("click", function () {
    var v = output.value;
    if (!v) { showToast(t("empty")); return; }
    var blob = new Blob([v], { type: "text/plain;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = mode === "encode" ? "base64-encoded.txt" : "base64-decoded.txt";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
    showToast(t("downloaded"));
  });

  $("langToggle").addEventListener("click", function () {
    lang = lang === "fa" ? "en" : "fa";
    store.set("b64-lang", lang);
    applyLang();
  });

  // Ripple effect on buttons
  document.querySelectorAll(".btn, .swap").forEach(function (btn) {
    btn.addEventListener("click", function (e) {
      var rect = btn.getBoundingClientRect();
      var circle = document.createElement("span");
      var d = Math.max(rect.width, rect.height);
      var radius = d / 2;
      circle.style.width = circle.style.height = d + "px";
      circle.style.left = (e.clientX - rect.left - radius) + "px";
      circle.style.top = (e.clientY - rect.top - radius) + "px";
      circle.classList.add("btn-ripple");
      var existing = btn.getElementsByClassName("btn-ripple")[0];
      if (existing) existing.remove();
      btn.appendChild(circle);
      setTimeout(function () { circle.remove(); }, 600);
    });
  });

  applyLang();
  setMode("encode");
})();
