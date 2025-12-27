(() => {
  let bubbleEl = null;
  let currentText = "";
  let hideTimer = null;

  // Auto-highlight settings (stored in chrome.storage.local)
  let hlSettings = {
    enabled: true,
    domains: true,
    ips: true,
    hashes: true,
    cves: true,
  };

  function loadHighlightSettings(cb){
    try{
      chrome.storage.local.get([
        "autoHighlightEnabled",
        "autoHighlightDomains",
        "autoHighlightIPs",
        "autoHighlightHashes",
        "autoHighlightCVEs",
      ], res => {
        hlSettings.enabled = res.autoHighlightEnabled !== false;
        hlSettings.domains = res.autoHighlightDomains !== false;
        hlSettings.ips = res.autoHighlightIPs !== false;
        hlSettings.hashes = res.autoHighlightHashes !== false;
        hlSettings.cves = res.autoHighlightCVEs !== false;
        cb && cb();
      });
    }catch(e){
      // If storage isn't available for some reason, default to enabled
      cb && cb();
    }
  }

  
  function refangBubble(s){
    if(!s) return s;
    let v = s.trim();
    v = v.replace(/\[\s*\.\s*\]/g, ".");
    v = v.replace(/\(\s*\.\s*\)/g, ".");
    v = v.replace(/\[\s*:\s*\]/g, ":");
    v = v.replace(/\s+dot\s+/gi, ".");
    v = v.replace(/^hxxps?:\/\//i, m => m.toLowerCase().startsWith("hxxps") ? "https://" : "http://");
    return v;
  }
  const RE_IPv4_BUB = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const RE_IPv6_BUB = /^[0-9a-f:]+$/i;
  const RE_DOMAIN_BUB = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
  // CVE format is CVE-YYYY-NNNN... (numeric part is 4+ digits; no fixed upper bound)
  const RE_CVE_BUB = /^CVE-(?:19|20)\d{2}-\d{4,}$/i;
  const RE_CVE_FIND = /\bCVE-(?:19|20)\d{2}-\d{4,}\b/i;

  // Avoid false positives like "loader.exe" being treated as a domain.
  // We only block extensions that are NOT valid TLDs (exe/dll/etc).
  const HS_BLOCKED_PSEUDO_TLDS = new Set([
    "exe","dll","msi","msp","bat","cmd","ps1","psm1","vbs","vbe","js","jse","wsf","wsh",
    "scr","cpl","sys","drv","jar","apk","ipa","dmg","pkg","deb","rpm","iso","img","bin",
    "zip","rar"
  ]);

  // Avoid false positives like AV/EDR detection names being treated as domains
  // e.g. "Trojan.Generic", "InfoStealer.Win.MythStealer", etc.
  const HS_BLOCKED_DOMAIN_PREFIXES = new Set([
    "trojan","worm","backdoor","virus","malware","ransomware","spyware","adware","riskware",
    "hacktool","pua","pup","unwanted","grayware","infostealer","stealer","keylogger",
    "dropper","loader","agent","generic","heuristic","suspicious","exploit"
  ]);

  function normalizeDomainToken(s){
    if(!s) return "";
    // strip common trailing punctuation
    return s.trim().replace(/[\]\)\}\>,;:!?\.]+$/g, "");
  }

  function isLikelyDomainToken(s){
    const raw = normalizeDomainToken((s||""));
    const v = raw.toLowerCase();
    if(!v) return false;
    if(v.includes("@")) return false; // emails
    const parts = v.split(".");
    if(parts.length < 2) return false;
    const first = parts[0];
    if(first && HS_BLOCKED_DOMAIN_PREFIXES.has(first)) return false;
    const tld = parts[parts.length-1];
    if(!tld || tld.length < 2) return false;
    if(HS_BLOCKED_PSEUDO_TLDS.has(tld)) return false;
    return true;
  }

  function looksLikeHashBubble(s){
    if(!s) return false;
    const hex = s.replace(/[^a-fA-F0-9]/g, "");
    if(!hex) return false;
    const len = hex.length;
    return [32,40,56,64,96,128].includes(len);
  }

function guessModeForBubble(raw){
  if (!raw) return "raw";

  const v = refangBubble(raw.trim());
  if (!v) return "raw";

  // 1) Hash wins first
  if (looksLikeHashBubble(v)) return "hash";

  // 1b) CVE
  if (RE_CVE_FIND.test(v)) return "cve";

  // 2) Try to get the host / base token
  let base = v;
  try {
    if (/^https?:\/\//i.test(v)) {
      // If it's a URL (even defanged originally), extract hostname
      const u = new URL(v);
      base = u.hostname;
    } else {
      base = v.split(/[\s/]/)[0];
    }
  } catch (e) {
    base = v.split(/[\s/]/)[0];
  }

  base = normalizeDomainToken(base);

  // 3) IP or domain on the host/base
  if (RE_IPv4_BUB.test(base) || RE_IPv6_BUB.test(base)) return "ip";
  if (RE_DOMAIN_BUB.test(base) && isLikelyDomainToken(base)) return "domain";

  return "raw";
}


function ensureBubble() {
    if (bubbleEl) return bubbleEl;
    bubbleEl = document.createElement("div");
    bubbleEl.id = "hunterscope-bubble";
    Object.assign(bubbleEl.style, {
      position: "absolute",
      zIndex: "2147483647",
      display: "none",
      padding: "4px",
      borderRadius: "999px",
      background: "rgba(15,23,42,0.96)",
      boxShadow: "0 8px 25px rgba(0,0,0,0.45)",
      color: "#e5e7eb",
      fontFamily: "system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif",
      fontSize: "11px",
      cursor: "pointer",
      alignItems: "center",
      border: "1px solid rgba(148,163,184,0.6)",
      display: "inline-flex",
      overflow: "hidden",
      minHeight: "32px",
      minWidth: "32px",
      maxHeight: "32px",
      transition: "background .15s ease, box-shadow .15s ease"
    });

    const iconSpan = document.createElement("span");
    iconSpan.style.width = "24px";
    iconSpan.style.height = "24px";
    iconSpan.style.flex = "0 0 24px";
    iconSpan.style.display = "flex";
    iconSpan.style.alignItems = "center";
    iconSpan.style.justifyContent = "center";
    iconSpan.style.borderRadius = "999px";
    const svg = `
      <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="7" stroke="white" stroke-width="2" fill="none"/>
        <line x1="12" y1="3" x2="12" y2="7" stroke="white" stroke-width="2"/>
        <line x1="12" y1="17" x2="12" y2="21" stroke="white" stroke-width="2"/>
        <line x1="3" y1="12" x2="7" y2="12" stroke="white" stroke-width="2"/>
        <line x1="17" y1="12" x2="21" y2="12" stroke="white" stroke-width="2"/>
        <circle cx="12" cy="12" r="2" fill="white"/>
      </svg>`;
    iconSpan.innerHTML = svg;
    const textSpan = document.createElement("span");
    textSpan.textContent = "HunterScope";
    textSpan.style.whiteSpace = "nowrap";
    textSpan.style.marginLeft = "0";
    textSpan.style.opacity = "0";
    textSpan.style.maxWidth = "0";
    textSpan.style.transition = "opacity .15s ease, max-width .2s ease, margin-left .2s ease";

    bubbleEl.appendChild(iconSpan);
    bubbleEl.appendChild(textSpan);

    bubbleEl.addEventListener("mousedown", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
    });

    bubbleEl.addEventListener("click", (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (!currentText) return;
      chrome.runtime.sendMessage({
        type: "HUNTERSCOPE_QUICK_ANALYZE",
        text: currentText
      });
      hideBubble();
    });

    bubbleEl.addEventListener("mouseenter", () => {
      bubbleEl.style.background = "rgba(37,99,235,0.95)";
      bubbleEl.style.boxShadow = "0 10px 30px rgba(15,23,42,0.7)";
      textSpan.style.marginLeft = "8px";
      textSpan.style.opacity = "1";
      textSpan.style.maxWidth = "160px";
    });

    bubbleEl.addEventListener("mouseleave", () => {
      bubbleEl.style.background = "rgba(15,23,42,0.96)";
      bubbleEl.style.boxShadow = "0 8px 25px rgba(0,0,0,0.45)";
      textSpan.style.marginLeft = "0";
      textSpan.style.opacity = "0";
      textSpan.style.maxWidth = "0";
    });

    document.documentElement.appendChild(bubbleEl);
    return bubbleEl;
  }

  function scheduleHideBubble(delayMs = 150){
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = setTimeout(() => hideBubble(), delayMs);
  }

  function cancelHideBubble(){
    if (hideTimer) clearTimeout(hideTimer);
    hideTimer = null;
  }

  function hideBubble() {
    if (bubbleEl) {
      bubbleEl.style.display = "none";
    }
  }

  function showBubbleAtRect(text, rect){
    if (!text || !rect) {
      currentText = "";
      hideBubble();
      return;
    }

    const mode = guessModeForBubble(text);
    if (!["ip","domain","hash","cve"].includes(mode)) {
      currentText = "";
      hideBubble();
      return;
    }

    let cleanedText = text;
    if (mode === "cve"){
      const m = String(text).toUpperCase().match(RE_CVE_FIND);
      if (m && m[0]) cleanedText = m[0];
    }

    currentText = cleanedText;
    const bubble = ensureBubble();

    const preferredTop = window.scrollY + rect.top - 4;
    const preferredLeft = window.scrollX + rect.right + 8;

    // Keep bubble inside viewport (best-effort)
    const bubbleW = 210; // conservative max width while expanded
    const bubbleH = 32;
    let top = preferredTop;
    let left = preferredLeft;
    const maxLeft = window.scrollX + window.innerWidth - bubbleW - 8;
    if (left > maxLeft) left = Math.max(window.scrollX + 8, window.scrollX + rect.left - bubbleW - 8);
    const maxTop = window.scrollY + window.innerHeight - bubbleH - 8;
    if (top > maxTop) top = Math.max(window.scrollY + 8, maxTop);

    bubble.style.top = `${top}px`;
    bubble.style.left = `${left}px`;
    bubble.style.display = "inline-flex";

    // reset to compact state each time it appears
    bubble.style.background = "rgba(15,23,42,0.96)";
    bubble.style.boxShadow = "0 8px 25px rgba(0,0,0,0.45)";
    const label = bubble.querySelector("span:nth-child(2)");
    if (label) {
      label.style.marginLeft = "0";
      label.style.opacity = "0";
      label.style.maxWidth = "0";
    }
  }

  function showBubbleForSelection() {
    const sel = window.getSelection();
    if (!sel || sel.isCollapsed) {
      currentText = "";
      hideBubble();
      return;
    }
    const text = sel.toString().trim();
    if (!text || text.length > 2048) {
      currentText = "";
      hideBubble();
      return;
    }
    const range = sel.getRangeAt(0);
    const rect = range.getBoundingClientRect();
    if (!rect || (!rect.width && !rect.height)) {
      hideBubble();
      return;
    }

    showBubbleAtRect(text, rect);
  }

  document.addEventListener("selectionchange", () => {
    setTimeout(showBubbleForSelection, 10);
  });

  window.addEventListener("scroll", () => {
    hideBubble();
  }, { passive: true });

  window.addEventListener("blur", () => {
    hideBubble();
  });

  // ------------------------------------------------------------
  // Auto-highlight (domains, IPs, hashes)
  // ------------------------------------------------------------

  const HS_IOC_CLASS = "hunterscope-ioc";
  const HS_STYLE_ID = "hunterscope-ioc-style";

  // Candidate regexes are intentionally broad; we validate after refanging.
  const RE_HASH_CAND = /\b[a-fA-F0-9]{32,128}\b/g;
  const RE_IPV4_CAND = /\b(?:\d{1,3}(?:\.|\[\.\]|\(\.\))){3}\d{1,3}\b/g;
  const RE_IPV6_CAND = /\b(?:(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}|::(?:[0-9A-Fa-f]{0,4}:){0,6}[0-9A-Fa-f]{0,4})\b/g;
  const RE_CVE_CAND  = /\bCVE-(?:19|20)\d{2}-\d{4,}\b/gi;
  const RE_DOMAIN_CAND = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.\]|\(\.\))){1,10}[a-zA-Z]{2,63}\b/g;

  function ensureHighlightStyles(){
    if (document.getElementById(HS_STYLE_ID)) return;
    const st = document.createElement("style");
    st.id = HS_STYLE_ID;
    st.textContent = `
      .${HS_IOC_CLASS}{
        /* Pill-style highlight (similar to CVE tag visuals) */
        background: rgba(124, 58, 237, 0.16);
        border: 1px solid rgba(124, 58, 237, 0.55);
        border-radius: 9999px;
        padding: 0.06em 0.45em;
        margin: 0 0.06em;
        cursor: pointer;
        text-decoration: none;
        -webkit-box-decoration-break: clone;
        box-decoration-break: clone;
        transition: background 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
      }
      .${HS_IOC_CLASS}:hover{
        background: rgba(124, 58, 237, 0.26);
        border-color: rgba(124, 58, 237, 0.85);
        box-shadow: 0 0 0 2px rgba(124, 58, 237, 0.14);
      }
      @media (prefers-color-scheme: dark){
        .${HS_IOC_CLASS}{
          background: rgba(167, 139, 250, 0.16);
          border-color: rgba(167, 139, 250, 0.55);
        }
        .${HS_IOC_CLASS}:hover{
          background: rgba(167, 139, 250, 0.26);
          border-color: rgba(167, 139, 250, 0.85);
          box-shadow: 0 0 0 2px rgba(167, 139, 250, 0.14);
        }
      }
    `;
    document.documentElement.appendChild(st);
  }

  function isValidIPv4(ip){
    const parts = (ip||"").split(".");
    if (parts.length !== 4) return false;
    for (const p of parts){
      if (!/^\d{1,3}$/.test(p)) return false;
      const n = Number(p);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }

  function isValidIPv6(ip){
    const v = (ip||"").trim();
    if (!v || v.length < 2) return false;
    try{
      // URL parsing validates IPv6 when bracketed
      new URL(`http://[${v}]/`);
      return true;
    }catch(e){
      return false;
    }
  }

  function findMatchesInText(text){
    const matches = [];
    if (!text || text.length < 6) return matches;

    if (hlSettings.hashes){
      for (const m of text.matchAll(RE_HASH_CAND)){
        const raw = m[0];
        const hex = raw.replace(/[^a-fA-F0-9]/g, "");
        if (!hex) continue;
        if (![32,40,56,64,96,128].includes(hex.length)) continue;
        matches.push({ start: m.index, end: m.index + raw.length, text: raw, mode: "hash" });
      }
    }

    if (hlSettings.ips){
      for (const m of text.matchAll(RE_IPV4_CAND)){
        const raw = m[0];
        const v = refangBubble(raw);
        if (!isValidIPv4(v)) continue;
        matches.push({ start: m.index, end: m.index + raw.length, text: raw, mode: "ip" });
      }
      for (const m of text.matchAll(RE_IPV6_CAND)){
        const raw = m[0];
        // Avoid highlighting times like "12:34" by requiring at least 2 colons
        if ((raw.match(/:/g) || []).length < 2) continue;
        if (!isValidIPv6(raw)) continue;
        matches.push({ start: m.index, end: m.index + raw.length, text: raw, mode: "ip" });
      }
    }

    if (hlSettings.domains){
      for (const m of text.matchAll(RE_DOMAIN_CAND)){
        const raw = m[0];
        const v = refangBubble(raw);
        if (!RE_DOMAIN_BUB.test(v)) continue;
        if (!isLikelyDomainToken(v)) continue;
        matches.push({ start: m.index, end: m.index + raw.length, text: raw, mode: "domain" });
      }
    }

    if (hlSettings.cves){
      for (const m of text.matchAll(RE_CVE_CAND)){
        const raw = m[0];
        // Normalize to canonical uppercase CVE-YYYY-NNNN...
        const v = raw.toUpperCase();
        if (!RE_CVE_BUB.test(v)) continue;
        matches.push({ start: m.index, end: m.index + raw.length, text: raw, mode: "cve" });
      }
    }

    if (!matches.length) return matches;

    // Sort + de-overlap (prefer hash > ip > domain)
    const prio = { cve: 4, hash: 3, ip: 2, domain: 1 };
    matches.sort((a,b)=> (a.start - b.start) || (b.end - a.end) || (prio[b.mode]-prio[a.mode]) );

    const out = [];
    for (const m of matches){
      const last = out[out.length-1];
      if (!last){ out.push(m); continue; }
      if (m.start >= last.end){ out.push(m); continue; }
      // overlap: keep the one that starts earlier; if same start, keep longer/higher prio
      if (m.start === last.start){
        const lastLen = last.end - last.start;
        const mLen = m.end - m.start;
        if (mLen > lastLen || (mLen === lastLen && prio[m.mode] > prio[last.mode])){
          out[out.length-1] = m;
        }
      }
    }
    return out;
  }

  function isSkippableTextNode(node){
    if (!node || !node.parentElement) return true;
    if (!node.nodeValue || !node.nodeValue.trim()) return true;
    const p = node.parentElement;
    if (p.closest(`#hunterscope-bubble, .${HS_IOC_CLASS}`)) return true;
    if (p.isContentEditable) return true;
    const tag = p.tagName;
    if (!tag) return false;
    return ["SCRIPT","STYLE","TEXTAREA","INPUT","NOSCRIPT","SELECT","OPTION"].includes(tag);
  }

  function highlightTextNode(node){
    const text = node.nodeValue;
    if (!text || text.length < 6) return;

    const matches = findMatchesInText(text);
    if (!matches.length) return;

    ensureHighlightStyles();

    const frag = document.createDocumentFragment();
    let lastIdx = 0;
    for (const m of matches){
      if (m.start > lastIdx) frag.appendChild(document.createTextNode(text.slice(lastIdx, m.start)));
      const span = document.createElement("span");
      span.className = HS_IOC_CLASS;
      span.textContent = m.text;
      span.dataset.hsValue = m.text;
      span.dataset.hsMode = m.mode;
      frag.appendChild(span);
      lastIdx = m.end;
    }
    if (lastIdx < text.length) frag.appendChild(document.createTextNode(text.slice(lastIdx)));
    node.parentNode && node.parentNode.replaceChild(frag, node);
  }

  function scanRoot(root){
    if (!root) return;
    const MAX_TEXT_NODES = 3500;
    const nodes = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())){
      if (nodes.length >= MAX_TEXT_NODES) break;
      if (isSkippableTextNode(n)) continue;
      // Skip extremely large text nodes (usually JSON blobs)
      if (n.nodeValue && n.nodeValue.length > 50000) continue;
      nodes.push(n);
    }
    for (const tn of nodes) highlightTextNode(tn);
  }

  function clearHighlights(){
    const els = document.querySelectorAll(`.${HS_IOC_CLASS}`);
    for (const el of els){
      const text = document.createTextNode(el.textContent || "");
      el.replaceWith(text);
    }
  }

  let scanScheduled = false;
  function scheduleScan(){
    if (scanScheduled) return;
    scanScheduled = true;
    setTimeout(() => {
      scanScheduled = false;
      if (!hlSettings.enabled) return;
      scanRoot(document.body || document.documentElement);
    }, 500);
  }

  function setupObserver(){
    if (!document.body) return;
    const obs = new MutationObserver((mutations) => {
      if (!hlSettings.enabled) return;
      for (const m of mutations){
        if (m.type === "childList" && (m.addedNodes && m.addedNodes.length)){
          scheduleScan();
          return;
        }
        if (m.type === "characterData"){
          scheduleScan();
          return;
        }
      }
    });
    obs.observe(document.body, { childList: true, subtree: true, characterData: true });
  }

  // Hover -> show bubble on highlighted IOCs
  document.addEventListener("mouseover", (ev) => {
    const el = ev.target && ev.target.closest ? ev.target.closest(`.${HS_IOC_CLASS}`) : null;
    if (!el) return;
    cancelHideBubble();
    const txt = (el.dataset.hsValue || el.textContent || "").trim();
    if (!txt) return;
    showBubbleAtRect(txt, el.getBoundingClientRect());
  }, true);

  document.addEventListener("mouseout", (ev) => {
    const from = ev.target && ev.target.closest ? ev.target.closest(`.${HS_IOC_CLASS}`) : null;
    if (!from) return;
    // If moving into the bubble, don't hide
    const toEl = ev.relatedTarget;
    if (toEl && bubbleEl && (toEl === bubbleEl || (toEl.closest && toEl.closest("#hunterscope-bubble")))) return;
    scheduleHideBubble(200);
  }, true);

  // Keep bubble visible while hovering it
  document.addEventListener("mouseover", (ev) => {
    if (ev.target && ev.target.closest && ev.target.closest("#hunterscope-bubble")) cancelHideBubble();
  }, true);
  document.addEventListener("mouseout", (ev) => {
    if (ev.target && ev.target.closest && ev.target.closest("#hunterscope-bubble")) scheduleHideBubble(200);
  }, true);

  function initAutoHighlight(){
    loadHighlightSettings(() => {
      if (hlSettings.enabled) {
        ensureHighlightStyles();
        scanRoot(document.body || document.documentElement);
        setupObserver();
      }
    });

    try{
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== "local") return;
        const keys = ["autoHighlightEnabled","autoHighlightDomains","autoHighlightIPs","autoHighlightHashes","autoHighlightCVEs"];
        const touched = keys.some(k => k in changes);
        if (!touched) return;

        loadHighlightSettings(() => {
          clearHighlights();
          if (hlSettings.enabled) scheduleScan();
        });
      });
    }catch(e){/* ignore */}
  }

  initAutoHighlight();

})();