
const CTX = ["selection","link","image","video","audio","editable","page"];

function refang(s){
  if(!s) return s;
  let v = s.trim();

  v = v.replace(/\[\s*\.\s*\]/g, ".");
  v = v.replace(/\(\s*\.\s*\)/g, ".");  
  v = v.replace(/\[\s*:\s*\]/g, ":");    
  v = v.replace(/\s+dot\s+/gi, ".");     

  v = v.replace(/^hxxps:\/\//i, "https://");
  v = v.replace(/^hxxp:\/\//i, "http://");

  return v;
}

const RE_IPv4=/^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_IPv6=/^[0-9a-f:]+$/i;
const RE_DOMAIN=/^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;
const RE_CVE=/^CVE-(?:19|20)\d{2}-\d{4,}$/i;
const RE_MD5=/^[a-f0-9]{32}$/i, RE_SHA1=/^[a-f0-9]{40}$/i, RE_SHA256=/^[a-f0-9]{64}$/i;

function getHost(u){ try{ return new URL(u).hostname; }catch(e){ return ""; } }
function pickInfo(info){
  const sel = refang((info.selectionText||"").trim());
  const link = info.linkUrl || "";
  const src  = info.srcUrl || "";
  const url  = refang(sel || link || src || "");
  const host = getHost(link) || getHost(src) || "";
  let token = sel;
  if(!token && host) token = host;
  return { sel, url, host, token };
}

const DEFAULT_CATEGORIES = [
  { id:"IP", name:"IP", mode:"ip", items:[
          {id:"IP_VT", name:"VirusTotal (IP)", url:"https://www.virustotal.com/gui/ip-address/{val}"},
          {id:"IP_ABUSEIPDB", name:"AbuseIPDB", url:"https://www.abuseipdb.com/check/{val}"},
          {id:"IP_GREYNOISE", name:"GreyNoise", url:"https://viz.greynoise.io/ip/{val}"},
          {id:"IP_URLSCAN", name:"urlscan (IP)", url:"https://urlscan.io/search/#ip:{val}"},
          {id:"IP_IPQUALITY", name:"IPQS", url:"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{val}"},
          {id:"IP_THREATFOX", name:"Threat Fox", url:"https://threatfox.abuse.ch/browse.php?search=ioc%3A{val}"},
          {id:"IP_SHODAN", name:"Shodan", url:"https://www.shodan.io/host/{val}"},
          {id:"IP_OTX", name:"OTX (IP)", url:"https://otx.alienvault.com/indicator/ip/{val}"},
          {id:"IP_URLQUERY", name:"UrlQuery", url:"https://urlquery.net/search?q={val}&view=&type=reports"}
  ]},
  { id:"DOMAIN", name:"Domain", mode:"domain", items:[
          {id:"DOM_VT", name:"VirusTotal (Domain)", url:"https://www.virustotal.com/gui/domain/{val}"},
          {id:"DOM_URLSCAN", name:"urlscan (Domain)", url:"https://urlscan.io/search/#domain:{val}"},
          {id:"DOM_URLQUERY", name:"Cisco Url Query", url:"https://urlquery.net/search?q={val}&view=&type=reports"},
          {id:"DOM_SYMANTEC", name:"Symantec", url:"https://sitereview.bluecoat.com/#/lookup-result/{val}"},
          {id:"DOM_OTX", name:"OTX (Domain)", url:"https://otx.alienvault.com/indicator/domain/{val}"}
  ]},
  { id:"HASH", name:"Hash", mode:"hash", items:[
          {id:"HASH_VT", name:"VirusTotal (File)", url:"https://www.virustotal.com/gui/file/{val}"},
          {id:"HASH_MALWAREBAZAAR", name:"MalwareBazaar", url:"https://bazaar.abuse.ch/browse.php?search=hash:{val}"},
          {id:"HASH_HYBRID", name:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/search?query={val}"},
          {id:"HASH_JOE", name:"Joe Sandbox", url:"https://www.joesandbox.com/analysis/search?q={val}"},
          {id:"HASH_ANYRUN", name:"ANY.RUN", url:"https://app.any.run/submissions/#filehash:{val}"},
          {id:"HASH_OTX", name:"OTX (File)", url:"https://otx.alienvault.com/indicator/file/{val}"}
  ]},
  { id:"CVE", name:"CVE", mode:"cve", items:[
          {id:"CVE_NVD", name:"NVD", url:"https://nvd.nist.gov/vuln/detail/{val}"},
          {id:"CVE_MITRE", name:"MITRE", url:"https://cve.mitre.org/cgi-bin/cvename.cgi?name={val}"},
          {id:"CVE_CVEDetails", name:"CVE Details", url:"https://www.cvedetails.com/cve/{val}/"},
          {id:"CVE_Vulners", name:"Vulners", url:"https://vulners.com/search?query={val}"},
          {id:"CVE_ExploitDB", name:"Exploit-DB Search", url:"https://www.exploit-db.com/search?cve={val}"}
  ]},
  { id:"CyberChef", name:"CyberChef", mode:"raw", items:[
    {id:"CyberChef_ParseUserAgent", name:"Parse User Agent", url:"https://gchq.github.io/CyberChef/#recipe=Parse_User_Agent()&input={b64}"},
    {id:"CyberChef_ExtractEmail", name:"Extract E-mail Addresses", url:"https://gchq.github.io/CyberChef/#recipe=Extract_email_addresses()&input={b64}"},
    {id:"CyberChef_ExtractDomains", name:"Extract Domains", url:"https://gchq.github.io/CyberChef/#recipe=Extract_domains()&input={b64}"},
    {id:"CyberChef_ExtractIPs", name:"Extract IPs", url:"https://gchq.github.io/CyberChef/#recipe=Extract_IP_addresses()&input={b64}"},
    {id:"CyberChef_Decodeb64", name:"Decode B64", url:"https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9+/=',true,false)&input={val}"}
  ]}
];

function loadCategories(){
  return new Promise(r=>chrome.storage.local.get(["categories"],res=>{
    const cats = Array.isArray(res.categories)&&res.categories.length ? res.categories : DEFAULT_CATEGORIES;
    r(cats);
  }));
}


async function getOpenInNewWindow(){
  const res = await chrome.storage.local.get(["openInNewWindow"]);
  return !!res.openInNewWindow;
}

function openTargets(urls, openInNewWindow){
  if(!Array.isArray(urls)) urls=[urls];
  urls = urls.filter(u=>!!u);
  if(!urls.length) return;
  if(openInNewWindow){
    chrome.windows.create({url: urls});
  }else{
    for(const url of urls){
      chrome.tabs.create({url});
    }
  }
}

async function buildMenus(){
  const cats = await loadCategories();
  await new Promise(res => chrome.contextMenus.removeAll(() => res()));
  for(const cat of cats){
    const parentId = "CAT__" + cat.id;
    try{ chrome.contextMenus.create({ id: parentId, title: cat.name, contexts: CTX }); }catch(e){}
    chrome.contextMenus.create({ id: parentId + "__OPEN_ALL", parentId, title:"Open in all", contexts: CTX });
    chrome.contextMenus.create({ id: parentId + "__SEP", parentId, type:"separator", contexts: CTX });
    for(const it of (cat.items||[])){
      chrome.contextMenus.create({ id: parentId + "__" + it.id, parentId, title: it.name||it.id, contexts: CTX });
    }
  }
}

chrome.runtime.onInstalled.addListener(buildMenus);

function looksLikeHash(s){
  if(!s) return false;
  const hex = s.replace(/[^a-fA-F0-9]/g, "");
  if(!hex) return false;
  const len = hex.length;
  return [32,40,56,64,96,128].includes(len);
}

function guessModeFromText(raw){
  if (!raw) return "raw";
  const v = refang(raw.trim());
  if (!v) return "raw";

  if (looksLikeHash(v)) return "hash";

  if (/\bCVE-(?:19|20)\d{2}-\d{4,}\b/i.test(v)) return "cve";

  let base = v;
  try {
    if (/^https?:\/\//i.test(v)) {
      const u = new URL(v);
      base = u.hostname;
    } else {
      base = v.split(/[\s/]/)[0];
    }
  } catch (e) {
    base = v.split(/[\s/]/)[0];
  }

  if (RE_IPv4.test(base) || RE_IPv6.test(base)) return "ip";
  if (RE_DOMAIN.test(base)) return "domain";

  return "raw";
}


async function quickAnalyzeSelection(text){
  if(!text) return;
  const cats = await loadCategories();
  const openInNewWindow = await getOpenInNewWindow();
  const mode = guessModeFromText(text);
  const ctx = pickCtx({ selectionText: text });
  const cat = cats.find(c => c.mode === mode) || cats.find(c => c.mode === "raw");
  if(!cat) return;
  const value = computeVal(cat.mode, ctx);
  if(!value) return;
  const enc = encodeURIComponent(value);
  const b64 = btoa(unescape(encodeURIComponent(value)));
  const urls = (cat.items||[]).map(it =>
    it.url.replace("{val}", enc).replace("{b64}", b64)
  );
  openTargets(urls, openInNewWindow);
}

chrome.runtime.onStartup?.addListener(buildMenus);
chrome.storage.onChanged.addListener(buildMenus);

function computeVal(mode, ctx){
  switch(mode){
    case "ip":
      return ctx.token || ctx.host || "";

    case "domain":
      return ctx.token || ctx.host || "";

    case "hash":
      return ctx.sel || ctx.token || "";

    case "cve": {
      const raw = (ctx.sel || ctx.token || "").toUpperCase();
      const m = raw.match(/\bCVE-(?:19|20)\d{2}-\d{4,}\b/);
      return (m && m[0]) ? m[0] : (ctx.sel || ctx.token || "");
    }

    case "url":
      // always return a fully fanged URL for URL category
      return refang(ctx.url || ctx.sel || "");

    case "host":
      return ctx.host || ctx.token || "";

    case "raw":
    default:
      return ctx.sel || ctx.token || ctx.url || "";
  }
}

function pickCtx(info){
  const sel = refang((info.selectionText||"").trim());
  const link = info.linkUrl || "";
  const src  = info.srcUrl || "";
  const url  = refang(sel || link || src || "");
  const host = ( ()=> { try { return new URL(link||src).hostname } catch { return "" } } )();
  const token = sel || host;
  return {sel,url,host,token};
}

chrome.contextMenus.onClicked.addListener(async (info,tab)=>{
  const cats = await loadCategories();
  const openInNewWindow = await getOpenInNewWindow();
  const ctx = pickCtx(info);
  for(const cat of cats){
    const pid="CAT__"+cat.id;
    if(info.menuItemId===pid+"__OPEN_ALL"){
      const value=computeVal(cat.mode, ctx);
      const enc=encodeURIComponent(value);
      const b64=btoa(unescape(encodeURIComponent(value)));
      const urls=(cat.items||[]).map(it=>
        it.url.replace("{val}", enc).replace("{b64}", b64)
      );
      openTargets(urls, openInNewWindow);
      return;
    }
    for(const it of (cat.items||[])){
      if(info.menuItemId===pid+"__"+it.id){
        const value=computeVal(cat.mode, ctx);
        const enc=encodeURIComponent(value);
        const b64=btoa(unescape(encodeURIComponent(value)));
        const url=it.url.replace("{val}", encodeURIComponent(value));
        const finalUrl=url.replace('{b64}', b64);
        openTargets(finalUrl, openInNewWindow);
        return;
      }
    }
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse)=>{
  if(msg && msg.type === "HUNTERSCOPE_QUICK_ANALYZE"){
    quickAnalyzeSelection(msg.text);
  }
});

chrome.action?.onClicked.addListener(() => {
  if(chrome.runtime.openOptionsPage){
    chrome.runtime.openOptionsPage();
  }else{
    chrome.tabs.create({url: chrome.runtime.getURL("options.html")});
  }
});
