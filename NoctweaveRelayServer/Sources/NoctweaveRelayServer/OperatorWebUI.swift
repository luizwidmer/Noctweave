import Foundation

enum OperatorWebUI {
    static let html = #"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <meta name="color-scheme" content="dark">
      <title>Noctweave Relay Console</title>
      <link rel="stylesheet" href="/admin/assets/app.css">
    </head>
    <body>
      <div class="ambient" aria-hidden="true"></div>
      <section class="login" id="login">
        <form class="loginCard" id="loginForm">
          <div class="brandMark">◇</div>
          <span class="eyebrow">Noctweave Relay</span>
          <h1>Operator Console</h1>
          <p>Manage this relay without exposing its control plane to messaging clients.</p>
          <label for="token">Admin token</label>
          <input id="token" type="password" autocomplete="current-password" required>
          <button class="primary" type="submit">Open Console</button>
          <p class="error" id="loginError" role="alert"></p>
        </form>
      </section>

      <main class="app" id="app" hidden>
        <aside class="rail">
          <div class="brand"><div class="brandMark small">◇</div><div><strong>Noctweave</strong><span>Relay Console</span></div></div>
          <nav id="navigation">
            <button data-view="overview" class="active"><span>◌</span> Overview</button>
            <button data-view="general"><span>◇</span> General</button>
            <button data-view="delivery"><span>⇄</span> Delivery</button>
            <button data-view="federation"><span>⌁</span> Federation</button>
            <button data-view="advanced"><span>⚙</span> Advanced</button>
          </nav>
          <div class="railStatus"><span class="onlineDot"></span><span id="railStatus">Relay online</span></div>
        </aside>

        <section class="content">
          <header class="topbar">
            <div><span class="eyebrow" id="viewEyebrow">Operations</span><h2 id="viewTitle">Overview</h2></div>
            <div class="actions"><span class="statusPill"><span class="onlineDot"></span><span id="headerRelay">Connected</span></span><button id="logout" class="quiet">Lock</button></div>
          </header>

          <section class="view active" data-view-panel="overview">
            <div class="heroCard"><div><span class="eyebrow">Current relay</span><h3 id="overviewName">Noctweave Relay</h3><p id="overviewEndpoint">Not advertised</p></div><span class="badge good">Running</span></div>
            <div class="metricGrid">
              <article><span>Uptime</span><strong id="uptime">—</strong></article>
              <article><span>Federation</span><strong id="overviewFederation">—</strong></article>
              <article><span>Storage</span><strong id="overviewStorage">—</strong></article>
              <article><span>Transport</span><strong id="overviewTransport">—</strong></article>
            </div>
            <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Bootstrap boundary</span><h3>Listener and storage settings</h3></div><span class="badge">Restart-controlled</span></div><dl class="details" id="bootstrapDetails"></dl><p class="hint">Bind addresses, ports, request ceilings, storage backend, and secrets are intentionally controlled by container arguments or environment variables.</p></div>
          </section>

          <form id="configForm">
            <section class="view" data-view-panel="general">
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Presentation</span><h3>Relay identity</h3></div></div><div class="fieldGrid"><label>Relay name<input name="relayName" maxlength="1024" placeholder="Community Relay"></label><label>Advertised endpoint<input name="advertisedEndpoint" maxlength="2048" placeholder="https://relay.example.org"></label></div><label>Operator message<textarea name="operatorNote" maxlength="1024" rows="4" placeholder="Optional information shown to clients"></textarea></label><div class="callout"><strong>Public endpoint</strong><span>Advertise the client-facing HTTPS, WSS, TLS, or TCP address. For a reverse proxy, use its public URL—not the container address.</span></div></div>
            </section>

            <section class="view" data-view-panel="delivery">
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Timing</span><h3>Temporal bucketing</h3></div></div><div class="fieldGrid"><label>Primary bucket (seconds)<input name="temporalBucketSeconds" type="number" min="0" max="86400"></label><label>Multi-bucket schedule<input name="temporalBucketScheduleSeconds" placeholder="60, 120, 300"></label></div><p class="hint">Set the primary bucket to 0 and leave the schedule empty to disable temporal bucketing. A schedule selects a stable bucket per routing identifier.</p></div>
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Payloads</span><h3>Attachments and groups</h3></div><label class="switch"><input name="attachmentsEnabled" type="checkbox"><span></span>Attachments</label></div><div class="fieldGrid three"><label>Default retention (seconds)<input name="attachmentDefaultTTLSeconds" type="number" min="60" max="21600"></label><label>Maximum retention (seconds)<input name="attachmentMaxTTLSeconds" type="number" min="60" max="21600"></label><label>Group creation<select name="groupCreationMode"><option value="allowed">Allowed</option><option value="disabled">Disabled</option></select></label></div></div>
            </section>

            <section class="view" data-view-panel="federation">
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Routing domain</span><h3>Federation mode</h3></div><span class="badge" id="federationBadge">Solo</span></div><div class="fieldGrid three"><label>Mode<select name="federationMode"><option value="solo">Solo</option><option value="manual">Manual</option><option value="curated">Curated</option><option value="open">Open</option></select></label><label>Federation name<input name="federationName" maxlength="1024"></label><label>Peer exchange limit<input name="relayPeerExchangeLimit" type="number" min="0" max="128"></label></div><label>Description<textarea name="federationDescription" maxlength="1024" rows="3"></textarea></label><div class="callout warning"><strong>Trust domains remain separate</strong><span>Solo, manual, curated, and open federation are not silently mixed. DHT and peer exchange are available only to open federation.</span></div></div>
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Peers</span><h3>Relay endpoints</h3></div></div><label>Allowed or manually federated relays<textarea name="federationAllowList" rows="5" placeholder="https://relay-a.example.org&#10;wss://relay-b.example.org"></textarea></label><label>Coordinator endpoints<textarea name="federationCoordinatorEndpoints" rows="4" placeholder="https://coordinator.example.org"></textarea></label><label class="switch openOnly"><input name="openFederationDHTEnabled" type="checkbox"><span></span>Run open-federation DHT node</label></div>
            </section>

            <section class="view" data-view-panel="advanced">
              <div class="sectionCard"><div class="cardHeader"><div><span class="eyebrow">Client wake policy</span><h3>Polling advertisement</h3></div></div><div class="fieldGrid three"><label>Mode<select name="wakeMode"><option value="disabled">Not advertised</option><option value="pullOnly">Pull only</option><option value="longPoll">Long poll</option></select></label><label>Minimum poll (seconds)<input name="wakeMinPollSeconds" type="number" min="5" max="86400"></label><label>Maximum poll (seconds)<input name="wakeMaxPollSeconds" type="number" min="5" max="86400"></label><label>Jitter (permille)<input name="wakeJitterPermille" type="number" min="0" max="1000"></label><label>Long-poll timeout<input name="wakeLongPollTimeoutSeconds" type="number" min="5" max="300"></label></div><div class="callout"><strong>Secrets stay outside the browser</strong><span>Relay passwords, admin tokens, coordinator registration tokens, and forwarding tokens remain environment or command-line settings and are never returned by this API.</span></div></div>
            </section>
          </form>

          <footer class="saveBar" id="saveBar" hidden><div><strong>Unsaved changes</strong><span>Validated changes apply to new relay requests immediately.</span></div><button id="discard" class="quiet">Discard</button><button id="save" class="primary">Save Changes</button></footer>
        </section>
      </main>
      <div class="toast" id="toast" hidden></div>
      <script src="/admin/assets/app.js" defer></script>
    </body>
    </html>
    """#

    static let css = #"""
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:#07090d;--surface:rgba(29,32,40,.82);--line:rgba(255,255,255,.105);--text:#f7f7fa;--muted:#9fa4b2;--accent:#8274ff;--accent2:#4ad5c2;--danger:#ff7382;--shadow:0 30px 100px rgba(0,0,0,.38)}
    *{box-sizing:border-box}[hidden]{display:none!important}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text)}.ambient{position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at 14% 8%,rgba(98,79,226,.23),transparent 38rem),radial-gradient(circle at 92% 72%,rgba(26,172,166,.15),transparent 36rem),linear-gradient(145deg,#07090d,#111723 58%,#071519)}button,input,textarea,select{font:inherit}button{border:1px solid rgba(151,139,255,.38);border-radius:14px;background:rgba(125,109,255,.16);color:var(--text);padding:10px 15px;cursor:pointer;transition:160ms ease}button:hover{transform:translateY(-1px);background:rgba(125,109,255,.27);border-color:rgba(171,161,255,.62)}button:disabled{opacity:.4;cursor:not-allowed}.primary{background:linear-gradient(135deg,#7867ed,#6759d1);box-shadow:0 10px 32px rgba(91,73,211,.22)}.quiet{background:rgba(255,255,255,.04);border-color:var(--line)}input,textarea,select{width:100%;border:1px solid var(--line);border-radius:14px;background:rgba(5,7,12,.62);color:var(--text);padding:12px 13px;outline:none;margin-top:7px}textarea{resize:vertical;line-height:1.5}input:focus,textarea:focus,select:focus{border-color:rgba(151,139,255,.76);box-shadow:0 0 0 3px rgba(125,109,255,.14)}label,.eyebrow{color:var(--muted);font-size:.73rem;font-weight:750;letter-spacing:.09em;text-transform:uppercase}.login{position:relative;z-index:3;min-height:100vh;display:grid;place-items:center;padding:24px}.loginCard{width:min(440px,100%);border:1px solid var(--line);border-radius:28px;background:rgba(22,25,33,.91);backdrop-filter:blur(34px);box-shadow:var(--shadow);padding:34px}.loginCard h1{margin:12px 0 8px;font-size:2rem}.loginCard p{color:var(--muted);line-height:1.55}.loginCard .primary{width:100%;margin-top:16px}.error{min-height:1.3em;color:#ff9da8!important}.brandMark{display:grid;place-items:center;width:58px;height:58px;border:1px solid rgba(151,139,255,.43);border-radius:18px;background:linear-gradient(145deg,rgba(125,109,255,.26),rgba(74,213,194,.1));font-size:2rem;color:#d8d2ff}.brandMark.small{width:42px;height:42px;border-radius:14px;font-size:1.4rem}.app{position:relative;z-index:1;min-height:100vh;display:grid;grid-template-columns:230px minmax(0,1fr)}.rail{position:sticky;top:0;height:100vh;border-right:1px solid var(--line);background:rgba(13,16,22,.68);backdrop-filter:blur(28px);padding:25px 18px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:11px;padding:0 7px 24px}.brand strong,.brand span{display:block}.brand span{color:var(--muted);font-size:.76rem;margin-top:2px}.rail nav{display:grid;gap:6px}.rail nav button{display:flex;align-items:center;gap:11px;border-color:transparent;background:transparent;text-align:left;color:#aeb3c0}.rail nav button span{width:20px;text-align:center}.rail nav button.active{color:#fff;background:rgba(125,109,255,.19);border-color:rgba(151,139,255,.2)}.railStatus{margin-top:auto;display:flex;align-items:center;gap:8px;padding:12px;color:var(--muted);font-size:.78rem}.onlineDot{width:8px;height:8px;border-radius:50%;background:var(--accent2);box-shadow:0 0 14px rgba(74,213,194,.65)}.content{min-width:0;padding:28px clamp(20px,4vw,52px) 110px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;max-width:1120px;margin:0 auto 24px}.topbar h2{font-size:1.75rem;margin:4px 0 0}.actions{display:flex;align-items:center;gap:9px}.statusPill,.badge{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.055);padding:9px 13px;font-size:.82rem}.badge.good{color:#87e9da;background:rgba(74,213,194,.08);border-color:rgba(74,213,194,.2)}.view{display:none;max-width:1120px;margin:0 auto}.view.active{display:grid;gap:14px;animation:enter .2s ease}.sectionCard,.heroCard,.metricGrid article{border:1px solid var(--line);background:var(--surface);backdrop-filter:blur(24px);box-shadow:var(--shadow);border-radius:22px}.sectionCard{padding:22px}.heroCard{padding:24px;display:flex;align-items:center;justify-content:space-between}.heroCard h3,.cardHeader h3{margin:4px 0 0;font-size:1.25rem}.heroCard p{color:var(--muted);margin:7px 0 0}.metricGrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metricGrid article{padding:18px}.metricGrid span,.metricGrid strong{display:block}.metricGrid span{color:var(--muted);font-size:.78rem}.metricGrid strong{margin-top:8px}.cardHeader{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}.fieldGrid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;margin-bottom:16px}.fieldGrid.three{grid-template-columns:repeat(3,1fr)}.callout{border:1px solid var(--line);border-radius:16px;background:rgba(255,255,255,.035);padding:15px;margin-top:16px}.callout strong,.callout span{display:block}.callout span,.hint{margin-top:5px;color:var(--muted);font-size:.83rem;line-height:1.5}.callout.warning{border-color:rgba(255,190,92,.2);background:rgba(255,190,92,.04)}.details{display:grid;grid-template-columns:180px minmax(0,1fr);gap:10px;margin:18px 0}.details dt{color:var(--muted)}.details dd{margin:0;overflow-wrap:anywhere}.switch{display:flex;align-items:center;gap:9px;text-transform:none;letter-spacing:0}.switch input{width:auto;margin:0}.switch span{width:34px;height:20px;border-radius:999px;background:#3b4050;position:relative}.switch span:after{content:"";position:absolute;width:14px;height:14px;left:3px;top:3px;border-radius:50%;background:#fff;transition:.16s}.switch input{position:absolute;opacity:0}.switch input:checked+span{background:#6f61df}.switch input:checked+span:after{transform:translateX(14px)}.saveBar{position:fixed;z-index:5;left:260px;right:30px;bottom:22px;max-width:1060px;margin:auto;border:1px solid rgba(151,139,255,.28);border-radius:19px;background:rgba(24,27,35,.94);backdrop-filter:blur(26px);box-shadow:var(--shadow);padding:13px 15px;display:flex;align-items:center;gap:10px}.saveBar div{margin-right:auto}.saveBar strong,.saveBar span{display:block}.saveBar span{color:var(--muted);font-size:.78rem;margin-top:3px}.toast{position:fixed;z-index:20;right:24px;bottom:24px;border:1px solid var(--line);border-radius:14px;background:rgba(27,31,40,.96);box-shadow:var(--shadow);padding:13px 16px}.toast.error{color:#ffacb5}@keyframes enter{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
    @media(max-width:820px){.app{grid-template-columns:1fr;padding-bottom:82px}.rail{position:fixed;z-index:10;inset:auto 10px 10px;height:auto;border:1px solid var(--line);border-radius:20px;padding:7px;background:rgba(24,28,36,.94)}.brand,.railStatus{display:none}.rail nav{grid-template-columns:repeat(5,1fr);gap:2px}.rail nav button{display:grid;justify-items:center;gap:2px;padding:8px 3px;font-size:.62rem}.content{padding:18px 14px 110px}.topbar{align-items:flex-start}.statusPill{display:none}.metricGrid,.fieldGrid,.fieldGrid.three{grid-template-columns:1fr}.saveBar{left:14px;right:14px;bottom:78px}.saveBar div{display:none}.details{grid-template-columns:1fr;gap:4px}.details dd{margin-bottom:8px}}
    """#

    static let javascript = #"""
    const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
    let token=sessionStorage.getItem("noctweaveAdminToken")||"", state=null, initialConfig="";
    const form=$("#configForm"), login=$("#login"), app=$("#app"), saveBar=$("#saveBar");
    const viewMeta={overview:["Operations","Overview"],general:["Relay","General"],delivery:["Policy","Delivery"],federation:["Network","Federation"],advanced:["Policy","Advanced"]};
    function api(path,options={}){return fetch(path,{...options,headers:{"Authorization":`Bearer ${token}`,"Content-Type":"application/json",...(options.headers||{})},cache:"no-store"}).then(async r=>{const data=await r.json().catch(()=>({error:"Invalid server response"}));if(!r.ok)throw new Error(data.error||`HTTP ${r.status}`);return data})}
    function showToast(message,error=false){const el=$("#toast");el.textContent=message;el.classList.toggle("error",error);el.hidden=false;setTimeout(()=>el.hidden=true,3200)}
    function lines(value){return value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean)}
    function configFromForm(){const d=new FormData(form), n=name=>Number(d.get(name)),open=d.get("federationMode")==="open";return{relayName:d.get("relayName").trim(),operatorNote:d.get("operatorNote").trim(),advertisedEndpoint:d.get("advertisedEndpoint").trim(),federationMode:d.get("federationMode"),federationName:d.get("federationName").trim(),federationDescription:d.get("federationDescription").trim(),federationAllowList:lines(d.get("federationAllowList")),federationCoordinatorEndpoints:lines(d.get("federationCoordinatorEndpoints")),temporalBucketSeconds:n("temporalBucketSeconds"),temporalBucketScheduleSeconds:d.get("temporalBucketScheduleSeconds").split(",").map(v=>v.trim()).filter(Boolean).map(Number),attachmentsEnabled:d.get("attachmentsEnabled")==="on",attachmentDefaultTTLSeconds:n("attachmentDefaultTTLSeconds"),attachmentMaxTTLSeconds:n("attachmentMaxTTLSeconds"),groupCreationMode:d.get("groupCreationMode"),relayPeerExchangeLimit:open?n("relayPeerExchangeLimit"):0,openFederationDHTEnabled:open&&d.get("openFederationDHTEnabled")==="on",wakeMode:d.get("wakeMode"),wakeMinPollSeconds:n("wakeMinPollSeconds"),wakeMaxPollSeconds:n("wakeMaxPollSeconds"),wakeJitterPermille:n("wakeJitterPermille"),wakeLongPollTimeoutSeconds:n("wakeLongPollTimeoutSeconds")}}
    function setField(name,value){const el=form.elements[name];if(!el)return;if(el.type==="checkbox")el.checked=!!value;else if(Array.isArray(value))el.value=name.includes("Schedule")?value.join(", "):value.join("\n");else el.value=value??""}
    function fill(data){state=data;Object.entries(data.configuration).forEach(([k,v])=>setField(k,v));initialConfig=JSON.stringify(configFromForm());saveBar.hidden=true;const c=data.configuration,s=data.status;$("#overviewName").textContent=c.relayName||"Unnamed Relay";$("#headerRelay").textContent=c.relayName||"Relay online";$("#overviewEndpoint").textContent=c.advertisedEndpoint||"No public endpoint advertised";$("#overviewFederation").textContent=c.federationMode;$("#overviewStorage").textContent=s.storage;$("#overviewTransport").textContent=s.transport;$("#federationBadge").textContent=c.federationMode;$("#uptime").textContent=formatDuration(s.uptimeSeconds);$("#bootstrapDetails").innerHTML=Object.entries(s.bootstrap).map(([k,v])=>`<dt>${escapeHTML(k)}</dt><dd>${escapeHTML(String(v))}</dd>`).join("");toggleMode()}
    function escapeHTML(v){return v.replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
    function formatDuration(seconds){const d=Math.floor(seconds/86400),h=Math.floor(seconds%86400/3600),m=Math.floor(seconds%3600/60);return d?`${d}d ${h}h`:h?`${h}h ${m}m`:`${m}m`}
    function toggleMode(){const open=form.elements.federationMode.value==="open";$$('.openOnly').forEach(el=>el.classList.toggle("disabled",!open));form.elements.openFederationDHTEnabled.disabled=!open;form.elements.relayPeerExchangeLimit.disabled=!open}
    async function load(){try{const data=await api("/admin/api/state");login.hidden=true;app.hidden=false;fill(data)}catch(e){token="";sessionStorage.removeItem("noctweaveAdminToken");login.hidden=false;app.hidden=true;$("#loginError").textContent=e.message}}
    $("#loginForm").addEventListener("submit",e=>{e.preventDefault();token=$("#token").value;sessionStorage.setItem("noctweaveAdminToken",token);load()});
    $("#logout").addEventListener("click",()=>{token="";sessionStorage.removeItem("noctweaveAdminToken");app.hidden=true;login.hidden=false;$("#token").value=""});
    $("#navigation").addEventListener("click",e=>{const b=e.target.closest("button[data-view]");if(!b)return;$$('#navigation button').forEach(x=>x.classList.toggle("active",x===b));$$('.view').forEach(v=>v.classList.toggle("active",v.dataset.viewPanel===b.dataset.view));[$("#viewEyebrow").textContent,$("#viewTitle").textContent]=viewMeta[b.dataset.view]});
    form.addEventListener("input",()=>{saveBar.hidden=JSON.stringify(configFromForm())===initialConfig;toggleMode()});
    $("#discard").addEventListener("click",()=>fill(state));
    $("#save").addEventListener("click",async()=>{const button=$("#save");button.disabled=true;try{const data=await api("/admin/api/config",{method:"PUT",body:JSON.stringify(configFromForm())});fill(data);showToast("Relay configuration saved") }catch(e){showToast(e.message,true)}finally{button.disabled=false}});
    if(token)load();
    """#
}
