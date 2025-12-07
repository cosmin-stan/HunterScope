(() => {
  let bubbleEl = null;
  let currentText = "";

  
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

  // 3) IP or domain on the host/base
  if (RE_IPv4_BUB.test(base) || RE_IPv6_BUB.test(base)) return "ip";
  if (RE_DOMAIN_BUB.test(base)) return "domain";

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

  function hideBubble() {
    if (bubbleEl) {
      bubbleEl.style.display = "none";
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

  const mode = guessModeForBubble(text);
if (!["ip","domain","hash"].includes(mode)) {
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

    currentText = text;
    const bubble = ensureBubble();
    const top = window.scrollY + rect.top - 4;
    const left = window.scrollX + rect.right + 8;
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

  document.addEventListener("selectionchange", () => {
    setTimeout(showBubbleForSelection, 10);
  });

  window.addEventListener("scroll", () => {
    hideBubble();
  }, { passive: true });

  window.addEventListener("blur", () => {
    hideBubble();
  });

})();