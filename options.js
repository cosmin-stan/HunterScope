
let CATS=[];
let idxSel=-1;

const listEl=document.getElementById("cats-list");
const tableBody=document.querySelector("#prov-table tbody");
const editor=document.getElementById("cat-editor");
const title=document.getElementById("cat-title");
const openInNewWindowEl=document.getElementById("open-in-new-window");

function load(){
  chrome.storage.local.get(["categories","openInNewWindow"], res=>{
    if(Array.isArray(res.categories)&&res.categories.length){ CATS=res.categories; }
    else{
      CATS=[
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
          {id:"HASH_MALWAREBAZAAR", name:"MalwareBazaar SHA256", url:"https://bazaar.abuse.ch/sample/{val}/"},
          {id:"HASH_HYBRID", name:"Hybrid Analysis", url:"https://www.hybrid-analysis.com/search?query={val}"},
          {id:"HASH_JOE", name:"Joe Sandbox", url:"https://www.joesandbox.com/analysis/search?q={val}"},
          {id:"HASH_ANYRUN", name:"ANY.RUN", url:"https://app.any.run/submissions/#filehash:{val}"},
          {id:"HASH_OTX", name:"OTX (File)", url:"https://otx.alienvault.com/indicator/file/{val}"}
        ]},
         { id:"CyberChef", name:"CyberChef", mode:"raw", items:[
          {id:"CyberChef_ParseUserAgent", name:"Parse User Agent", url:"https://gchq.github.io/CyberChef/#recipe=Parse_User_Agent()&input={b64}"},
          {id:"CyberChef_ExtractEmail", name:"Extract E-mail Addresses", url:"https://gchq.github.io/CyberChef/#recipe=Extract_email_addresses()&input={b64}"},
          {id:"CyberChef_ExtractDomains", name:"Extract Domains", url:"https://gchq.github.io/CyberChef/#recipe=Extract_domains()&input={b64}"},
          {id:"CyberChef_ExtractIPs", name:"Extract IPs", url:"https://gchq.github.io/CyberChef/#recipe=Extract_IP_addresses()&input={b64}"},
          {id:"CyberChef_Decodeb64", name:"Decode B64", url:"https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9+/=',true,false)&input={val}"}
  ]}
      ];
    }
    openInNewWindowEl.checked = !!res.openInNewWindow;
    renderList();
    if(CATS.length) select(0);
  });
}

function renderList(){
  listEl.innerHTML="";
  CATS.forEach((c,i)=>{
    const div=document.createElement("div");
    div.className="cat-item"+(i===idxSel?" sel":"");
    div.textContent=`${c.name} (${c.mode})`;
    div.onclick=()=> select(i);
    listEl.appendChild(div);
  });
}

function select(i){
  idxSel=i;
  renderList();
  const c=CATS[i];
  if(!c){ editor.classList.add("hidden"); return; }
  editor.classList.remove("hidden");
  title.textContent=`Category: ${c.name}`;
  document.getElementById("edit-id").value=c.id;
  document.getElementById("edit-name").value=c.name;
  document.getElementById("edit-mode").value=c.mode;

  tableBody.innerHTML="";
  (c.items||[]).forEach((it,idx)=>{
    const tr=document.createElement("tr");
    tr.innerHTML=`
      <td><input class="pid" value="${it.id||""}"></td>
      <td><input class="pnm" value="${it.name||""}"></td>
      <td><input class="purl" value="${it.url||""}"></td>
      <td class="move"><button class="up">↑</button><button class="down">↓</button></td>
      <td><button class="del">Delete</button></td>`;
    tr.querySelector(".pid").oninput=e=> it.id=e.target.value.trim();
    tr.querySelector(".pnm").oninput=e=> it.name=e.target.value.trim();
    tr.querySelector(".purl").oninput=e=> it.url=e.target.value.trim();
    tr.querySelector(".up").onclick=()=>{ if(idx>0){ [c.items[idx-1],c.items[idx]]=[c.items[idx],c.items[idx-1]]; select(i); } };
    tr.querySelector(".down").onclick=()=>{ if(idx<c.items.length-1){ [c.items[idx+1],c.items[idx]]=[c.items[idx],c.items[idx+1]]; select(i); } };
    tr.querySelector(".del").onclick=()=>{ c.items.splice(idx,1); select(i); };
    tableBody.appendChild(tr);
  });
}

document.getElementById("cat-add").onclick=()=>{
  const id=document.getElementById("cat-id").value.trim();
  const nm=document.getElementById("cat-name").value.trim();
  const mode=document.getElementById("cat-mode").value;
  if(!id||!nm) return alert("Fill category ID and Name.");
  CATS.push({id, name:nm, mode, items:[]});
  document.getElementById("cat-id").value="";
  document.getElementById("cat-name").value="";
  renderList(); select(CATS.length-1);
};

document.getElementById("cat-save").onclick=()=>{
  const c=CATS[idxSel]; if(!c) return;
  c.id=document.getElementById("edit-id").value.trim()||c.id;
  c.name=document.getElementById("edit-name").value.trim()||c.name;
  c.mode=document.getElementById("edit-mode").value;
  renderList(); select(idxSel);
};

document.getElementById("cat-delete").onclick=()=>{
  if(idxSel<0) return;
  if(!confirm("Delete this category?")) return;
  CATS.splice(idxSel,1); idxSel=-1; renderList(); editor.classList.add("hidden");
};

document.getElementById("prov-add").onclick=()=>{
  const c=CATS[idxSel]; if(!c) return;
  const id=document.getElementById("prov-id").value.trim();
  const nm=document.getElementById("prov-name").value.trim();
  const url=document.getElementById("prov-url").value.trim();
  if(!id||!nm||!url||(!url.includes("{val}") && !url.includes("{b64}"))) return alert("Provider needs ID, Name, and URL with {val} or {b64}.");
  c.items.push({id, name:nm, url});
  document.getElementById("prov-id").value="";
  document.getElementById("prov-name").value="";
  document.getElementById("prov-url").value="";
  select(idxSel);
};

document.getElementById("save-all").onclick=()=>{
  for(const c of CATS){
    if(!c.id||!c.name) return alert("Each category needs ID and Name.");
    for(const it of (c.items||[])){
      if(!it.id||!it.name||!it.url||(!it.url.includes("{val}") && !it.url.includes("{b64}")))
        return alert("Every provider needs ID, Name, and URL with {val} or {b64}.");
    }
  }
  const openInNewWindow = openInNewWindowEl.checked;
  chrome.storage.local.set({categories:CATS, openInNewWindow},()=>{
    const s=document.getElementById("status"); s.textContent="Saved ✓"; setTimeout(()=> s.textContent="", 1200);
  });
};

document.getElementById("reset").onclick=()=>{
  chrome.storage.local.remove(["categories","openInNewWindow"], ()=> load());
};

document.addEventListener("DOMContentLoaded", load);
