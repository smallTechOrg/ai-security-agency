import React,{useEffect,useState}from'react';
import{createRoot}from'react-dom/client';
import{Shield,Activity,FileText,CheckCircle,AlertTriangle,DollarSign,Brain,LockKeyhole,LayoutDashboard,ScanLine,ShieldCheck,Users,ListChecks,ScrollText,CalendarClock,Receipt,Radio,Wrench,ChevronRight,GitBranch,Code2,KeyRound}from'lucide-react';
import'./style.css';
const API=import.meta.env.VITE_API_BASE_URL||((typeof location!=='undefined'&&location.port==='5173')?'http://127.0.0.1:8011':'');

class EB extends React.Component{constructor(p){super(p);this.state={e:null}}static getDerivedStateFromError(e){return{e}}componentDidCatch(e){console.error('BOUND ERR',e&&e.message,e&&e.stack)}
  render(){if(this.state.e)return <div className="empty" style={{padding:40}}>View error: {String(this.state.e.message||this.state.e)}</div>;return this.props.children}}

function App(){
  const[view,setView]=useState('overview');
  const[health,setHealth]=useState(null),[dash,setDash]=useState(null),[admin,setAdmin]=useState(null),[domains,setDomains]=useState(null),[auditLog,setAuditLog]=useState(null),[billing,setBilling]=useState(null),[schedules,setSchedules]=useState(null),[tickets,setTickets]=useState(null),[summary,setSummary]=useState(null),[readiness,setReadiness]=useState(null),[users,setUsers]=useState(null),[costGov,setCostGov]=useState(null),[intelModels,setIntelModels]=useState(null),[intelMode,setIntelMode]=useState('deterministic'),[url,setUrl]=useState('https://example.com'),[tier,setTier]=useState('free'),[payment,setPayment]=useState(''),[run,setRun]=useState(null),[report,setReport]=useState(null),[timeline,setTimeline]=useState(null),[tasks,setTasks]=useState(null),[agentMesh,setAgentMesh]=useState(null),[intel,setIntel]=useState(null),[enterprise,setEnterprise]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  async function api(path,options){const r=await fetch(API+path,options),j=await r.json().catch(()=>({detail:r.statusText}));if(!r.ok)throw new Error(j.detail||`HTTP ${r.status}`);return j}
  async function load(){try{setHealth(await api('/health'));setDash(await api('/api/dashboard'));setAdmin(await api('/api/admin/domain-queue'));setDomains(await api('/api/admin/domains'));setAuditLog(await api('/api/admin/audit-log'));setBilling(await api('/api/billing/plans'));setSchedules(await api('/api/admin/schedules'));setTickets(await api('/api/remediation-tickets'));setSummary(await api('/api/program/summary'));setReadiness(await api('/api/program/readiness'));setUsers(await api('/api/admin/users'));const m=await api('/api/intelligence/models');setIntelModels(m);setIntelMode(m.current)}catch(e){}}
  useEffect(()=>{load()},[]);
  function clearReport(){setReport(null);setTimeline(null);setTasks(null);setAgentMesh(null);setIntel(null);setEnterprise(null)}
  async function buyDetailed(){setBusy(true);setError('');try{const p=await api('/api/payments/intent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target_url:url,scan_tier:'detailed'})});setPayment(p.payment_reference);setTier('detailed')}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function mintUpi(){setBusy(true);setError('');setUpi(null);try{const p=await api('/api/payments/upi-qr',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({plan:'vanguard'})});setUpi(p);setTier('detailed')}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function loadKeys(){try{setKeys(await api('/api/admin/access-keys'))}catch(e){}}
  async function activateKey(k){setBusy(true);try{await api(`/api/admin/access-key/${k}/activate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin',reason:'UPI confirmed'})});await loadKeys()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function revokeKey(k){setBusy(true);try{await api(`/api/admin/access-key/${k}/revoke`,{method:'POST'});await loadKeys()}catch(e){setError(e.message)}finally{setBusy(false)}}
  useEffect(()=>{if(view==='keys')loadKeys()},[view]);
  async function start(){setBusy(true);setError('');clearReport();const useKey=Boolean(upiKey.trim());try{
    const j=await api('/api/bootstrap',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target_url:url,client_name:'Vanguard Client',workspace_name:'Zer0 Security Program',budget_usd:tier==='detailed'?49:2.0,scan_tier:tier,payment_reference:payment,access_key:useKey?upiKey.trim():''})});
    setRun({...j,stage:'scanning',progress:15});setView('scans');
    const id=j.run_id;
    if(j.status==='awaiting_approval'){
      // One-click flow: auto admin-approve, run baseline, browser recon, then open the report with results.
      await api(`/api/runs/${id}/approve`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin (demo auto-approve)',reason:'Authorized demo scan.'})});
      const executed=await api(`/api/runs/${id}/execute`,{method:'POST'});setRun({...executed,stage:'browser recon',progress:70});
      try{await api(`/api/runs/${id}/browser-recon`,{method:'POST'});}catch(e){/* browser recon optional; baseline results still show */}
      // Human-in-the-loop: pause if a CAPTCHA/login/MFA wall was detected.
      const iv=await api(`/api/runs/${id}/intervention`).catch(()=>null);
      if(iv&&iv.needed){setIntervention({...iv,run_id:id,workspace_id:j.workspace_id});setBusy(false);return;}
      try{await api(`/api/runs/${id}/active-probe`,{method:'POST'});}catch(e){/* active probe optional; authorized domains only */}
      try{await api(`/api/runs/${id}/api-probe`,{method:'POST'});}catch(e){/* API probe optional */}
      await api(`/api/workspaces/${j.workspace_id}/enterprise-program`,{method:'POST'}).catch(()=>{});
      await load();
      await openRun({run_id:id,workspace_id:j.workspace_id,status:'completed'});
    } else {
      await load();setError('This detailed scan needs payment/approval. Use a free scan for instant results, or enable demo unlock.');
    }
  }catch(e){setError(e.message)}finally{setBusy(false)}}
  async function openRun(r){const id=r.run_id||r.id;setBusy(true);setError('');setRun({run_id:id,workspace_id:r.workspace_id,asset_id:r.asset_id||0,status:r.status,stage:r.stage,progress:r.progress,app_model:r.app_model||{}});clearReport();try{if(['awaiting_approval','payment_required','queued'].includes(r.status)){if(r.workspace_id)setCostGov(await api(`/api/workspaces/${r.workspace_id}/cost-governor?run_id=${id}`));return;}const [rep,tl,tk,mesh,ai,ent,gov]=await Promise.all([api(`/api/runs/${id}/report`),api(`/api/runs/${id}/timeline`),api(`/api/runs/${id}/tasks`),api(`/api/runs/${id}/agent-mesh`),api(`/api/runs/${id}/intelligence`),api(`/api/workspaces/${r.workspace_id}/enterprise`),api(`/api/workspaces/${r.workspace_id}/cost-governor?run_id=${id}`)]);setReport(rep);setTimeline(tl);setTasks(tk);setAgentMesh(mesh);setIntel(ai);setEnterprise(ent);setCostGov(gov);setView('report')}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function approve(){const active=run?.status==='awaiting_approval'?run:dash?.runs?.[0]?.status==='awaiting_approval'?dash.runs[0]:null;if(!active)return setError('Create a free audit or paid detailed scan first; admin approval unlocks testing.');const id=active.run_id||active.id;setBusy(true);setError('');try{await api(`/api/runs/${id}/approve`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin',reason:'Domain ownership and testing scope approved.'})});const executed=await api(`/api/runs/${id}/execute`,{method:'POST'});setRun(executed);const br=await api(`/api/runs/${id}/browser-recon`,{method:'POST'});setRun({...executed,status:br.status,stage:br.stage,progress:br.progress});await api(`/api/workspaces/${active.workspace_id}/enterprise-program`,{method:'POST'});await load();await openRun({...executed,status:br.status,stage:br.stage,progress:br.progress})}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function approveQueueRun(x){setBusy(true);setError('');try{const approved=await api(`/api/admin/domain-queue/${x.run_id}/approve`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin',reason:'Domain owner/admin approved from Vanguard queue.'})});setRun(approved);await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function executeQueueRun(x){setBusy(true);setError('');try{const done=await api(`/api/admin/domain-queue/${x.run_id}/execute`,{method:'POST'});await load();await openRun({...done,id:done.run_id})}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function revokeDomain(x){setBusy(true);setError('');try{await api(`/api/admin/domains/${x.asset_id}/revoke`,{method:'POST'});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function enableSchedule(x){setBusy(true);setError('');try{await api(`/api/admin/schedules/${x.workspace_id}/enable`,{method:'POST'});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function closeTicket(t){setBusy(true);setError('');try{await api(`/api/remediation-tickets/${t.id}/status`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({status:'closed'})});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function retestTicket(t){setBusy(true);setError('');try{await api(`/api/remediation-tickets/${t.id}/retest`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({outcome:'ready_for_retest',reviewer:'analyst',evidence_note:'Client reports fix ready for Vanguard retest.'})});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function pickIntelMode(e){const m=e.target.value;setIntelMode(m);try{await api('/api/intelligence/models',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({mode:m})})}catch(err){setError(err.message)}}

  const newestRun=dash?.runs?.[0],pendingRun=run?.status==='awaiting_approval'?run:(newestRun?.status==='awaiting_approval'?newestRun:null),current=run||newestRun,findings=report?.findings||dash?.findings||[],commerce=dash?.commerce||{};
  const open=tickets?.tickets?.filter(t=>t.status!=='closed').length;
  const nav=[{id:'overview',label:'Overview',icon:LayoutDashboard},{id:'scans',label:'Scans',icon:ScanLine,badge:dash?.runs?.length},{id:'mesh',label:'Agent mesh',icon:GitBranch,badge:agentMesh?.agent_status?.length},{id:'authtest',label:'Auth testing',icon:LockKeyhole},{id:'approvals',label:'Domain approvals',icon:ShieldCheck,badge:admin?.items?.filter(x=>x.status==='pending').length},{id:'domains',label:'Domain registry',icon:Radio},{id:'remediation',label:'Remediation',icon:ListChecks,badge:open},{id:'schedules',label:'Schedules',icon:CalendarClock},{id:'team',label:'Team & RBAC',icon:Users},{id:'billing',label:'Billing',icon:Receipt},{id:'audit',label:'Audit log',icon:ScrollText},{id:'readiness',label:'Launch readiness',icon:Wrench},{id:'repo',label:'Repo analysis',icon:Code2},{id:'keys',label:'Access keys',icon:KeyRound}];
  const[repo,setRepo]=useState(null);
  const[intervention,setIntervention]=useState(null);
  async function resumeIntervention(){if(!intervention)return;setBusy(true);setError('');const id=intervention.run_id,wid=intervention.workspace_id;try{await api(`/api/runs/${id}/intervention/resume`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({solved:true,note:'human solved CAPTCHA/login, resumed'})});try{await api(`/api/runs/${id}/active-probe`,{method:'POST'})}catch(e){}setIntervention(null);await load();await openRun({run_id:id,workspace_id:wid,status:'completed'})}catch(e){setError(e.message)}finally{setBusy(false)}}
  const[upi,setUpi]=useState(null);
  const[upiKey,setUpiKey]=useState('');
  const[keys,setKeys]=useState(null);

  return (
    <div className="app">
      <aside className="side">
        <div className="brand"><div className="logo"><Shield size={20}/></div><div><b>Vanguard</b><br/><small>by Zer0</small></div></div>
        <nav className="nav">{nav.map(n=><button key={n.id} className={view===n.id?'active':''} onClick={()=>setView(n.id)}><n.icon size={17}/>{n.label}{n.badge?n.badge>0&&<span className="badge">{n.badge}</span>:null}</button>)}</nav>
        <div className="foot">A security agent for your company.</div>
      </aside>
      <div className="main">
        <div className="topbar">
          <div className="title"><b>{nav.find(n=>n.id===view)?.label||'Console'}</b><p>Vanguard by Zer0 · enterprise web exposure control plane</p></div>
          <div className="spacer"/>
          <div className="health">
            <span className="chip"><span className={'dot '+(health?.provider?.openai?'ok':'')}/>OpenAI {health?.provider?.openai?'ready':'off'}</span>
            <span className="chip"><span className={'dot '+(health?.provider?.gemini?'ok':'')}/>Gemini {health?.provider?.gemini?'ready':'off'}</span>
          </div>
          <label className="modelpick">AI model<select value={intelMode} onChange={pickIntelMode}>{intelModels?.models?.map(m=><option key={m.id} value={m.id}>{m.label}</option>)}</select></label>
        </div>
        <div className="content">
          {error&&<div className="error">{error}</div>}
          {intervention&&<div className="panel" style={{border:'2px solid #f7b955',background:'linear-gradient(180deg,rgba(247,185,85,0.12),transparent)',marginBottom:16}}>
            <h3><LockKeyhole size={16}/> ⏸ Human intervention needed <span className="pill warn">{intervention.kind?.replace(/_/g,' ')||'takeover'}</span></h3>
            <p style={{marginTop:6}}>{intervention.reason}</p>
            {intervention.screenshot_url&&<div style={{marginTop:10}}><img src={`${API}${intervention.screenshot_url}`} alt="Page requiring human action" style={{maxWidth:'100%',borderRadius:12,border:'1px solid #263d5b'}}/></div>}
            <div className="row" style={{marginTop:12}}><button className="btn" disabled={busy} onClick={resumeIntervention}>{busy?'Resuming…':'✓ I solved it — resume scan'}</button><button className="btn ghost" disabled={busy} onClick={()=>setIntervention(null)}>Dismiss</button></div>
          </div>}
          {view==='overview'&&<Overview dash={dash} summary={summary} readiness={readiness} costGov={costGov} current={current} pendingRun={pendingRun} tier={tier} setTier={setTier} url={url} setUrl={setUrl} start={start} buyDetailed={buyDetailed} approve={approve} billing={billing} busy={busy} payment={payment} intelModels={intelModels} intelMode={intelMode} pickIntelMode={pickIntelMode} upi={upi} setUpi={setUpi} mintUpi={mintUpi} upiKey={upiKey} setUpiKey={setUpiKey}/>}
          {view==='scans'&&<Scans dash={dash} run={run} openRun={openRun} current={current}/>}
          {view==='mesh'&&<AgentMesh mesh={agentMesh} run={run}/>} 
          {view==='authtest'&&<AuthTesting current={current} setError={setError}/>} 
          {view==='approvals'&&<Approvals admin={admin} onApprove={approveQueueRun} onExecute={executeQueueRun}/>}
          {view==='domains'&&<Domains domains={domains} onRevoke={revokeDomain}/>}
          {view==='remediation'&&<Remediation tickets={tickets} onClose={closeTicket} onRetest={retestTicket}/>}
          {view==='schedules'&&<Schedules schedules={schedules} onEnable={enableSchedule}/>}
          {view==='team'&&<Team users={users}/>}
          {view==='billing'&&<Billing billing={billing} summary={summary}/>}
          {view==='audit'&&<AuditLogView log={auditLog}/>}
          {view==='readiness'&&<Readiness readiness={readiness}/>}
          {view==='repo'&&<RepoAnalyze repo={repo} setRepo={setRepo} busy={busy} setBusy={setBusy} setError={setError}/>}
          {view==='keys'&&<AccessKeys keys={keys} onActivate={activateKey} onRevoke={revokeKey}/>}
          {view==='report'&&report&&<ReportView report={report} intel={intel} enterprise={enterprise} tasks={tasks} timeline={timeline} agentMesh={agentMesh} costGov={costGov} onClose={()=>setView('scans')}/>}
        </div>
      </div>
    </div>
  );
}

function StatusBar({current}){if(!current)return null;return <div className="statusbar"><Activity size={18} color="#36d399"/><div><b>{current.status}</b><span> · {current.stage}</span></div><div className="prog"><progress max="100" value={current.progress||0}/></div><span>{current.progress||0}%</span></div>}
function Pill({kind,children}){return <span className={'pill '+kind}>{children}</span>}
function StatusPill({s}){const v=s||'unknown';const k={completed:'ok',browser_recon_complete:'ok',report_ready:'ok',approved:'ok',human_verified:'ok',active:'ok',retest_passed:'ok',retest_ready:'info',awaiting_approval:'warn',payment_required:'bad',queued:'info',needs_human_setup:'warn',retest_failed:'bad',domain_revoked:'bad',cancelled:'bad'}[v]||'mut';return <Pill kind={k}>{String(v).replace(/_/g,' ')}</Pill>}

function Overview({dash,summary,readiness,costGov,current,pendingRun,tier,setTier,url,setUrl,start,buyDetailed,approve,billing,busy,payment,intelModels,intelMode,pickIntelMode,upi,setUpi,mintUpi,upiKey,setUpiKey}){
  const s=summary?.operations||{}, rev=summary?.commerce||{}, risk=summary?.risk||{}, com=dash?.commerce||{};
  return <div className="view">
    <div className="hero">
      <span className="eyebrow">Enterprise web exposure management</span>
      <h2>Audit a public domain with approvals, budget controls, and evidence.</h2>
      <p>Start with a free high-level posture check. Detailed scans are payment-gated and require backend admin domain approval before any testing runs.</p>
      <div className="pricing">
        <button className={tier==='free'?'selected':''} onClick={()=>setTier('free')}><b>Free audit</b><span>Headers, TLS, public evidence</span></button>
        <button className={tier==='detailed'?'selected':''} onClick={buyDetailed}><b>Detailed scan · ${com.detailed_scan_price_usd||49}</b><span>Paid intent + admin domain approval</span></button>
      </div>
      {tier==='detailed'&&<div className="upi">
        <div className="upi-head"><LockKeyhole size={16}/> Pay with UPI (₹{upi?.amount_inr||49})</div>
        {!upi&&<button className="btn" disabled={busy} onClick={mintUpi}>{busy?'Generating…':'Generate UPI QR'}</button>}
        {upi&&<>
          <div className="qrbox">
            <div className="qr-meta"><b>{upi.upi_id}</b><span>₹{upi.amount_inr} · Vanguard</span></div>
            <a className="upi-link" href={upi.upi_string}>{upi.upi_string}</a>
            <div className="hint">Scan with any UPI app. After payment, the admin activates your access key below.</div>
            <div className="keyrow"><span className="keylabel">Access key</span><code>{upi.access_key}</code></div>
          </div>
          <div className="row"><input value={upiKey} onChange={e=>setUpiKey(e.target.value)} placeholder="Paste your activated access key to run deep audit"/><button className="btn" disabled={busy} onClick={()=>setUpi(null)}>Clear</button></div>
        </>}
      </div>}
      <div className="row"><input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://target-domain.com"/><button className="btn" disabled={busy} onClick={start}>{busy?'Working…':tier==='free'?'Start free audit':'Request detailed scan'}</button>{pendingRun&&<button className="btn ghost" disabled={busy} onClick={approve}>Admin approve + run</button>}</div>
      {payment&&<div className="hint"><LockKeyhole size={16}/> Payment intent staged: <b>{payment}</b></div>}
      {billing&&<div className="hint">Billing: stub checkout intents + Stripe-ready webhook.</div>}
    </div>
    <StatusBar current={current}/>
    <div className="grid">
      <div className="card"><div className="ic"><DollarSign size={18}/></div><h3>Budget remaining</h3><b>${costGov?.remaining_usd??rev.estimated_scan_revenue_usd??dash?.cost?.estimated_total_usd??0}</b><p>{costGov?`${costGov.allowed?'Allowed':'Blocked'} · projected $${costGov.projected_run_cost_usd}`:'Cost governor active'}</p></div>
      <div className="card good"><div className="ic"><CheckCircle size={18}/></div><h3>Approved domains</h3><b>{s.domains_approved??dash?.approvals?.length??0}</b><p>Admin-approved attack surface</p></div>
      <div className={'card '+((risk.open_remediation_tickets>0)?'alert':'good')}><div className="ic"><AlertTriangle size={18}/></div><h3>Open tickets</h3><b>{risk.open_remediation_tickets??0}</b><p>Remediation workload</p></div>
      <div className="card"><div className="ic"><Brain size={18}/></div><h3>Launch readiness</h3><b>{readiness?.ready_score??0}%</b><p>Readiness checklist</p></div>
    </div>
    <div className="mission"><h3>Vanguard control plane</h3><p>Domain intake → payment tier → admin approval → safe audit execution → evidence timeline → executive report → remediation program.</p></div>
  </div>;
}

function Scans({dash,run,openRun,current}){
  const runs=dash?.runs||[];
  return <div className="view">
    <StatusBar current={current}/>
    <div className="panel"><h3>Scan runs <span className="count">{runs.length}</span></h3>
      {runs.length===0&&<div className="empty">No scans yet. Start one from the Overview tab.</div>}
      {runs.map(r=><div key={r.id} className={'item runitem '+((run?.run_id||run?.id)===r.id?'selected':'')} onClick={()=>openRun(r)}>
        <div className="top"><b>Run #{r.id}</b>{StatusPill(r.status)}</div>
        <span className="sub">{r.stage}</span>
        <span className="meta">{(r.app_model?.scan_tier||'legacy')} · ${r.cost_estimate_usd} · workspace {r.workspace_id}</span>
      </div>)}
    </div>
  </div>;
}

function AgentMesh({mesh,run}){
  if(!mesh)return <div className="view"><div className="hero"><span className="eyebrow">Multi-agent control plane</span><h2>No agent mesh loaded yet.</h2><p>Open a completed scan from the Scans tab to run the Supervisor, Threat Analyst, Red Team, Remediation, Compliance, Evidence QA, and Reporter agents over its evidence.</p></div></div>;
  const outputs=mesh.outputs||{};
  return <div className="view">
    <div className="hero">
      <span className="eyebrow">Multi-agent security agency</span>
      <h2>Seven specialist agents reviewed run #{mesh.run_id||run?.run_id}.</h2>
      <p>Agents hand off evidence, risk chains, remediation, compliance mapping, and client-safe reporting under a no-exploit safety boundary.</p>
      <div className="hint">Cost guardrail: {mesh.cost_guardrail?.policy}</div>
    </div>
    <div className="grid">{(mesh.agent_status||[]).map(a=><div key={a.agent} className={'card '+(a.llm_backed?'good':'')}><div className="ic"><GitBranch size={18}/></div><h3>{a.agent}</h3><b>{a.llm_backed?'LLM':'Deterministic'}</b><p>{a.source} · {a.status}</p></div>)}</div>
    <div className="cols2">
      <div className="panel"><h3>Supervisor decision record</h3><p>{outputs.supervisor?.decision_record}</p><div className="hint">Next agent: {outputs.supervisor?.next_agent}</div></div>
      <div className="panel"><h3>Evidence QA</h3><p>{outputs.evidence_qa?.ready_for_client?'All report claims have baseline evidence.':'Evidence gaps require review before client delivery.'}</p>{(outputs.evidence_qa?.gaps||[]).map((g,i)=><div key={i} className="log">{g.severity} · {g.title} · {g.gap}</div>)}</div>
    </div>
    <div className="panel"><h3>Agent handoffs</h3>{(mesh.handoffs||[]).map((h,i)=><div key={i} className="item"><div className="top"><b>{h.from} → {h.to}</b><Pill kind="info">{h.artifact}</Pill></div></div>)}</div>
    <div className="panel"><h3>Risk register</h3>{(mesh.risk_register||[]).map(r=><div key={r.risk_id} className="item"><div className="top"><b><span className={'sev '+r.severity}>{r.severity}</span>{r.title}</b><Pill kind="mut">{r.sla}</Pill></div><span className="meta">{r.risk_id} · owner {r.owner}</span></div>)}</div>
    <div className="cols2"><div className="panel"><h3>Compliance Mapper</h3><pre>{outputs.compliance?.control_map}</pre></div><div className="panel"><h3>Remediation Engineer</h3><pre>{outputs.remediation?.fixes}</pre></div></div>
  </div>;
}

function AuthTesting({current,setError}){
  const[busy,setBusy]=useState(false),[state,setState]=useState(null),[result,setResult]=useState(null);
  const wid=current?.workspace_id, rid=current?.run_id||current?.id;
  async function call(path,options){const r=await fetch(API+path,options),j=await r.json().catch(()=>({detail:r.statusText}));if(!r.ok)throw new Error(j.detail||`HTTP ${r.status}`);return j}
  async function load(){if(!wid)return;const [creds,sessions,rules]=await Promise.all([call(`/api/workspaces/${wid}/credentials`),call(`/api/workspaces/${wid}/auth-sessions`),call(`/api/workspaces/${wid}/scope-rules`)]);setState({creds,sessions,rules})}
  useEffect(()=>{load().catch(e=>setError(e.message))},[wid]);
  async function seed(){if(!wid)return setError('Open a scan first.');setBusy(true);try{
    const c=await call(`/api/workspaces/${wid}/credentials`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({label:'Vanguard managed test account',username:'security-admin@example.com',secret_ref:'external-secret-not-stored',role_name:'standard_user'})});
    await call(`/api/workspaces/${wid}/scope-rules`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({include_pattern:'/*',exclude_pattern:'/logout,/delete,/billing,/settings/destructive',test_level:'safe_forms_dry_run'})});
    await call(`/api/workspaces/${wid}/auth-sessions`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credential_id:c.credential.id,status:'human_verified',success_indicator:'dashboard'})});
    await load();
  }catch(e){setError(e.message)}finally{setBusy(false)}}
  async function runDry(){if(!rid)return setError('Open a completed scan first.');setBusy(true);setResult(null);try{const out=await call(`/api/runs/${rid}/authenticated-form-test`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({dry_run:true,reviewer:'admin',reason:'Authorized authenticated safe-form dry run.'})});setResult(out);await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  return <div className="view">
    <div className="hero"><span className="eyebrow">Authenticated app testing workflow</span><h2>Prepare credential stubs, scope rules, and safe form dry-runs.</h2><p>Vanguard stores only external secret references, requires domain approval, and blocks live form submissions. This phase reviews authenticated forms without sending credentials or changing state.</p><div className="row"><button className="btn" disabled={busy||!wid} onClick={seed}>{busy?'Working…':'Seed credential + auth session'}</button><button className="btn ghost" disabled={busy||!rid} onClick={runDry}>Run safe form dry-run</button></div></div>
    <div className="grid"><div className="card"><div className="ic"><KeyRound size={18}/></div><h3>Credential stubs</h3><b>{state?.creds?.credentials?.length||0}</b><p>No secrets stored</p></div><div className="card"><div className="ic"><LockKeyhole size={18}/></div><h3>Auth sessions</h3><b>{state?.sessions?.sessions?.length||0}</b><p>Human verified profiles</p></div><div className="card"><div className="ic"><ShieldCheck size={18}/></div><h3>Scope rules</h3><b>{state?.rules?.rules?.length||0}</b><p>Excludes destructive paths</p></div><div className="card good"><div className="ic"><ListChecks size={18}/></div><h3>Last dry-run</h3><b>{result?.forms_reviewed??0}</b><p>{result?`${result.blocked_forms} blocked · no live submit`:'Not run'}</p></div></div>
    <div className="cols2"><div className="panel"><h3>Credentials</h3>{(state?.creds?.credentials||[]).map(c=><div key={c.id} className="item"><div className="top"><b>{c.label}</b><Pill kind="info">{c.role_name}</Pill></div><span className="meta">{c.username} · {c.secret_ref}</span></div>)}</div><div className="panel"><h3>Auth sessions</h3>{(state?.sessions?.sessions||[]).map(s=><div key={s.id} className="item"><div className="top"><b>session #{s.id}</b>{StatusPill(s.status)}</div><span className="meta">asset {s.asset_id} · credential {s.credential_id} · indicator {s.success_indicator}</span></div>)}</div></div>
    {result&&<div className="panel"><h3>Safe form dry-run result <span className="pill ok">no live submission</span></h3>{result.reviewed.map(f=><div key={f.index} className="item"><div className="top"><b>{f.method} {f.action}</b><Pill kind={f.decision==='blocked'?'warn':'ok'}>{f.decision}</Pill></div><span className="sub">inputs: {(f.inputs||[]).join(', ')||'none'} · reasons: {(f.reasons||[]).join(', ')||'none'}</span></div>)}</div>}
  </div>;
}

function Approvals({admin,onApprove,onExecute}){
  const items=(admin?.items||[]).filter(Boolean);
  return <div className="view"><div className="panel"><h3>Admin domain queue <span className="count">{items.length}</span></h3>
    {items.length===0&&<div className="empty">No pending domain approvals.</div>}
    {items.map(x=><div key={x.approval_id} className="item">
      <div className="top"><b>{x.domain||'domain pending'}</b>{StatusPill(x.status)}</div>
      <span className="sub">{x.scan_tier} · {x.payment_status} · run #{x.run_id}</span>
      <div className="row" style={{marginTop:8}}>{x.status==='pending'&&<button className="btn" onClick={()=>onApprove(x)}>Approve domain</button>}{x.status==='approved'&&x.run_status==='queued'&&<button className="btn" onClick={()=>onExecute(x)}>Run scan</button>}</div>
    </div>)}
  </div></div>;
}

function Domains({domains,onRevoke}){
  const d=domains?.domains||[];
  return <div className="view"><div className="panel"><h3>Domain registry <span className="count">{d.length}</span></h3>
    {d.length===0&&<div className="empty">No domains registered.</div>}
    {d.map(x=><div key={x.asset_id} className="item">
      <div className="top"><b>{x.url}</b>{x.authorized?<Pill kind="ok">approved</Pill>:<Pill kind="bad">revoked</Pill>}</div>
      <span className="meta">asset #{x.asset_id} · workspace {x.workspace_id}</span>
      {x.authorized&&<button className="btn danger" onClick={()=>onRevoke(x)}>Revoke</button>}
    </div>)}
  </div></div>;
}

function Remediation({tickets,onClose,onRetest}){
  const t=tickets?.tickets||[];
  return <div className="view"><div className="panel"><h3>Remediation tickets <span className="count">{t.length}</span></h3>
    {t.length===0&&<div className="empty">No remediation tickets. Run a scan to generate them from findings.</div>}
    {t.map(x=><div key={x.id} className="item">
      <div className="top"><b><span className={'sev '+x.severity}>{x.severity}</span>{x.title}</b>{StatusPill(x.status)}</div>
      <span className="meta">owner {x.owner} · finding #{x.finding_id}{x.retest_run_id?` · retest run #${x.retest_run_id}`:''}</span>
      <div className="row" style={{marginTop:8}}>{x.status!=='closed'&&<button className="btn ghost" onClick={()=>onClose(x)}>Close ticket</button>}{!x.status?.startsWith('retest_')&&<button className="btn" onClick={()=>onRetest(x)}>Create retest</button>}</div>
    </div>)}
  </div></div>;
}

function Schedules({schedules,onEnable}){
  const s=schedules?.schedules||[];
  return <div className="view"><div className="panel"><h3>Recurring schedules <span className="count">{s.length}</span></h3>
    {s.length===0&&<div className="empty">No schedules yet. Enable weekly Vanguard scans for an approved, subscribed workspace.</div>}
    {s.map(x=><div key={x.id} className="item">
      <div className="top"><b>workspace {x.workspace_id}</b>{StatusPill(x.status)}</div>
      <span className="sub">{x.cadence}</span><span className="meta">{x.next_run_note}</span>
      {x.status!=='active'&&<button className="btn" onClick={()=>onEnable(x)}>Enable weekly</button>}
    </div>)}
  </div></div>;
}

function Team({users}){
  const u=users?.users||[];
  return <div className="view"><div className="panel"><h3>Team roles <span className="count">{u.length}</span></h3>
    {u.length===0&&<div className="empty">No team members configured.</div>}
    {u.map(x=><div key={x.id} className="item">
      <div className="top"><b>{x.email}</b><Pill kind="info">{x.role}</Pill></div>
      <span className="meta">workspace {x.workspace_id}</span>
    </div>)}
  </div></div>;
}

function Billing({billing,summary}){
  const plans=billing?.plans||{};
  return <div className="view">
    <div className="cols2">
      <div className="panel"><h3>Plans</h3>
        <div className="item"><div className="top"><b>Free</b><Pill kind="ok">${plans.free?.price_usd??0}</Pill></div><span className="sub">{plans.free?.audits}</span></div>
        <div className="item"><div className="top"><b>Vanguard</b><Pill kind="info">${plans.vanguard?.price_usd??49}</Pill></div><span className="sub">{plans.vanguard?.audits}</span></div>
      </div>
      <div className="panel"><h3>Subscription status</h3>
        <div className="item"><div className="top"><b>Active Vanguard</b><Pill kind="ok">{summary?.commerce?.active_vanguard??0}</Pill></div><span className="sub">Subscriptions total: {summary?.commerce?.subscriptions_total??0}</span></div>
        <div className="item"><div className="top"><b>Est. scan revenue</b><Pill kind="mut">${summary?.commerce?.estimated_scan_revenue_usd??0}</Pill></div></div>
      </div>
    </div>
  </div>;
}

function AuditLogView({log}){
  const e=log?.events||[];
  return <div className="view"><div className="panel"><h3>Immutable audit log <span className="count">{e.length}</span></h3>
    {e.length===0&&<div className="empty">No audit events recorded.</div>}
    {e.map(x=><div key={x.id} className="log">{x.created_at} · <b>{x.actor}</b> · {x.action} · run {x.run_id}</div>)}
  </div></div>;
}

function Readiness({readiness}){
  const r=readiness?.checks||[];
  return <div className="view">
    <div className="card"><div className="ic"><Brain size={18}/></div><h3>Overall readiness</h3><b>{readiness?.ready_score??0}%</b><p>{readiness?.product}</p></div>
    <div className="panel"><h3>Launch checklist</h3>
      {r.map(c=><div key={c.name} className="item"><div className="top"><b>{c.name.replace(/_/g,' ')}</b>{c.ready?<Pill kind="ok">ready</Pill>:<Pill kind="warn">pending</Pill>}</div><span className="sub">{c.detail}</span></div>)}
    </div>
  </div>;
}

function ReportView({report,intel,enterprise,tasks,timeline,agentMesh,costGov,onClose}){
  return <div className="view"><div className="report">
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}><h2><FileText/> Vanguard security report</h2><button className="btn ghost" onClick={onClose}>← Back to scans</button></div>
    <div className="actions"><a href={`${API}/api/runs/${report.run_id}/report.html`} target="_blank">Open HTML report</a><a href={`${API}/api/runs/${report.run_id}/evidence-bundle`} target="_blank">Evidence JSON</a><a href={`${API}/api/client/reports/${report.run_id}`} target="_blank">Client-safe</a><a href={`${API}/api/runs/${report.run_id}/attestation`} target="_blank">Attestation</a></div>
    {(()=>{const sc=report.security_score,col=sc>=80?'#36d399':sc>=50?'#f7b955':'#ff5c7c',rb=report.detailed_depth?.risk_breakdown;return <div style={{display:'flex',gap:20,alignItems:'center',marginTop:14,padding:20,borderRadius:18,border:`1px solid ${col}55`,background:`linear-gradient(120deg, ${col}18, transparent)`}}>
      <div style={{flexShrink:0,width:96,height:96,borderRadius:'50%',display:'grid',placeItems:'center',border:`4px solid ${col}`,background:`${col}12`}}><div style={{textAlign:'center'}}><div style={{fontSize:30,fontWeight:800,lineHeight:1,color:col}}>{sc}</div><div style={{fontSize:10,opacity:0.6}}>/100</div></div></div>
      <div style={{flex:1}}>
        <div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:8}}>
          <span className="pill" style={{background:`${col}22`,color:col,border:`1px solid ${col}55`}}>{sc>=80?'LOW RISK':sc>=50?'MODERATE RISK':'ELEVATED RISK'}</span>
          {rb&&<span className="pill mut">{rb.total} findings · {Object.entries(rb.by_severity||{}).map(([k,v])=>`${v} ${k}`).join(' · ')}</span>}
          <span className="pill info">{report.scan_tier==='detailed'?'Detailed':'Free'} scan</span>
        </div>
        <p style={{margin:0,lineHeight:1.6,fontSize:15}}>{report.executive_summary}</p>
      </div>
    </div>;})()}
    {costGov&&<div className="hint">Cost governor: {costGov.allowed?'within budget':'over budget'} · remaining ${costGov.remaining_usd} · projected ${costGov.projected_run_cost_usd}</div>}
    {report.deep_analysis&&<div className="panel" style={{marginTop:16,border:'1px solid #7c5cff',background:'linear-gradient(180deg,rgba(124,92,255,0.10),transparent)'}}>
      <h3><Brain size={16}/> Deep analysis <span className={'pill '+(report.deep_analysis.llm_backed?'info':'mut')}>{report.deep_analysis.llm_backed?`senior-pentester LLM · ${report.deep_analysis.source}`:'deterministic'}</span></h3>
      <pre style={{marginTop:8,whiteSpace:'pre-wrap',lineHeight:1.6,background:'#0d1b2f',padding:14,borderRadius:12,border:'1px solid #263d5b',fontFamily:'inherit'}}>{report.deep_analysis.findings_text}</pre>
    </div>}
    {report.active_probe&&<div className="panel" style={{marginTop:16,border:'1px solid #ff5c7c',background:'linear-gradient(180deg,rgba(255,92,124,0.09),transparent)'}}>
      <h3><ScanLine size={16}/> Penetration test — active probes <span className="pill bad">{report.active_probe.findings} issues</span><span className="pill mut">{report.active_probe.checks_run} checks · non-destructive</span></h3>
      <div style={{marginTop:8}}>{(report.active_probe.checks||[]).map((c,i)=><div key={i} className="item" style={{borderLeft:'2px solid '+(c.issue_found?'#ff5c7c':'#36d399')}}><div className="top"><b>{c.issue_found?'⚠️':'✓'} {c.check}</b><span className={'pill '+(c.issue_found?'bad':'ok')}>{c.issue_found?c.severity:'pass'}</span></div>{c.title&&<span className="sub">{c.title}</span>}</div>)}</div>
    </div>}
    {report.api_security&&<div className="panel" style={{marginTop:16,border:'1px solid #d9a441'}}>
      <h3><Code2 size={16}/> API security test <span className={'pill '+(report.api_security.issues>0?'bad':'ok')}>{report.api_security.issues} issues</span><span className="pill mut">{report.api_security.endpoints_tested} observed · {report.api_security.discovered_count||0} discovered</span></h3>
      {(report.api_security.discovered||[]).length>0&&<div style={{marginBottom:8}}><h4>Discovered API surface</h4>{report.api_security.discovered.map((x,i)=><div key={i} className="item" style={{borderLeft:'2px solid #ff5c7c'}}><div className="top"><b>⚠️ {x.label} <code>{x.path}</code></b><span className={'sev '+x.severity}>{x.severity}</span></div><span className="sub">HTTP {x.status}</span></div>)}</div>}
      {report.api_security.endpoints_tested===0&&(report.api_security.discovered_count||0)===0&&<p className="sub">No API/XHR calls observed and no common API endpoints exposed.</p>}
      {report.api_security.endpoints_tested>0&&<h4>APIs the frontend calls</h4>}
      {(report.api_security.endpoints||[]).map((e,i)=><div key={i} className="item" style={{borderLeft:'2px solid '+(e.issue_count>0?'#ff5c7c':'#36d399')}}><div className="top"><b>{e.issue_count>0?'⚠️':'✓'} {e.method} {(()=>{try{return new URL(e.url).pathname}catch{return e.url}})()}</b><span className={'pill '+(e.issue_count>0?'bad':'ok')}>{e.issue_count>0?e.issue_count+' issue'+(e.issue_count>1?'s':''):'ok'}</span></div></div>)}
    </div>}
    {report.redteam&&<div className="panel" style={{marginTop:16,border:'1px solid #ff5c7c'}}>
      <h3><AlertTriangle size={16}/> Red Team agent — attack chain <span className={'pill '+(report.redteam.llm_backed?'bad':'mut')}>{report.redteam.llm_backed?`LLM · ${report.redteam.source}`:'deterministic'}</span></h3>
      <pre style={{marginTop:8,whiteSpace:'pre-wrap',lineHeight:1.6,background:'#1a0d14',padding:14,borderRadius:12,border:'1px solid #3a1f28'}}>{report.redteam.attack_chain}</pre>
    </div>}
    {report.reporter&&<div className="panel" style={{marginTop:16}}>
      <h3><FileText size={16}/> Reporter sub-agent <span className={'pill '+(report.reporter.llm_backed?'ok':'mut')}>{report.reporter.llm_backed?`LLM · ${report.reporter.source}`:'deterministic'}</span></h3>
      <p style={{marginTop:8,lineHeight:1.6}}>{report.reporter.assessment}</p>
    </div>}
    {report.remediation&&<div className="panel" style={{marginTop:16}}>
      <h3><Wrench size={16}/> Remediation Engineer sub-agent <span className={'pill '+(report.remediation.llm_backed?'ok':'mut')}>{report.remediation.llm_backed?`LLM · ${report.remediation.source}`:'deterministic'}</span></h3>
      <pre style={{marginTop:8,whiteSpace:'pre-wrap',background:'#0d1b2f',padding:14,borderRadius:12,border:'1px solid #263d5b',lineHeight:1.5}}>{report.remediation.fixes}</pre>
    </div>}
    {report.observability&&report.observability.llm_calls>0&&<div className="panel" style={{marginTop:16,border:'1px solid #2f81f7',background:'linear-gradient(180deg,rgba(47,129,247,0.08),transparent)'}}>
      <h3><Activity size={16}/> Agent observability <span className="pill info">LLM tracing</span></h3>
      <div className="grid" style={{marginTop:8}}>
        <div className="card"><div className="ic"><Brain size={18}/></div><h3>LLM calls</h3><b>{report.observability.llm_calls}</b><p>{report.observability.successful} ok · {report.observability.failovers} failover</p></div>
        <div className="card"><div className="ic"><Activity size={18}/></div><h3>Avg latency</h3><b>{report.observability.avg_latency_ms}ms</b><p>total {report.observability.total_latency_ms}ms</p></div>
        <div className="card"><div className="ic"><ShieldCheck size={18}/></div><h3>Providers</h3><b style={{fontSize:14}}>{(report.observability.providers_used||[]).join(', ')||'none'}</b><p>resilient failover</p></div>
      </div>
      <div style={{marginTop:10}}>{report.observability.calls.map((c,i)=><div key={i} className="log">{c.ok?'✓':'✗'} {c.agent} · {c.provider}/{c.model} · {c.latency_ms}ms{c.fallback?' · fallback'+(c.error?' ('+c.error+')':''):''}</div>)}</div>
    </div>}
    {agentMesh&&<div className="panel" style={{marginTop:16,border:'1px solid #36d399',background:'linear-gradient(180deg,rgba(54,211,153,0.07),transparent)'}}>
      <h3><GitBranch size={16}/> Multi-agent control plane <span className="pill ok">{agentMesh.agent_status?.length||0} agents</span></h3>
      <p style={{marginTop:8,lineHeight:1.6}}>{agentMesh.outputs?.supervisor?.decision_record}</p>
      <div className="grid" style={{marginTop:8}}>{(agentMesh.agent_status||[]).map(a=><div key={a.agent} className="card"><div className="ic"><GitBranch size={18}/></div><h3>{a.agent}</h3><b>{a.llm_backed?'LLM':'Deterministic'}</b><p>{a.source}</p></div>)}</div>
    </div>}
    {report.memory?.long_term&&<div className="panel" style={{marginTop:16,border:'1px solid #d9a441',background:'linear-gradient(180deg,rgba(217,164,65,0.08),transparent)'}}>
      <h3><Brain size={16}/> Agent memory <span className="pill mut">accumulating</span></h3>
      <div className="grid" style={{marginTop:8}}>
        <div className="card"><div className="ic"><CalendarClock size={18}/></div><h3>Scans remembered</h3><b>{report.memory.long_term.scans}</b><p>trend: {report.memory.long_term.trend||'stable'}</p></div>
        <div className="card"><div className="ic"><Activity size={18}/></div><h3>Score history</h3><b>{(report.memory.long_term.score_history||[]).join(' → ')}</b><p>best {report.memory.long_term.best_score} · worst {report.memory.long_term.worst_score}</p></div>
        <div className="card"><div className="ic"><ListChecks size={18}/></div><h3>Recurring issues</h3><b>{(report.memory.long_term.top_recurring||[]).length}</b><p>tracked across scans</p></div>
      </div>
      {(report.memory.long_term.top_recurring||[]).length>0&&<div style={{marginTop:10}}><h4>Recurring findings (long-term memory)</h4>{report.memory.long_term.top_recurring.map((r,i)=><div key={i} className="log">{r[0]} · seen <b>{r[1]}×</b></div>)}</div>}
      {report.memory.short_term?.length>0&&<div style={{marginTop:10}}><h4>Short-term memory (recent scans)</h4>{report.memory.short_term.slice(0,5).map((s,i)=><div key={i} className="log">#{s.run_id} · {s.tier} · score {s.score} · {s.findings_total} findings</div>)}</div>}
    </div>}
    {report.detailed_depth&&(()=>{const paid=report.scan_tier==='detailed';const accent=paid?'#7c5cff':'#2f81f7';return <div className="panel" style={{marginTop:16,border:`1px solid ${accent}`,background:`linear-gradient(180deg,${paid?'rgba(124,92,255,0.10)':'rgba(47,129,247,0.10)'},transparent)`}}>
      <h3><ShieldCheck size={16}/> {paid?'Vanguard Detailed Depth':'Security Depth Analysis'} <span className={'pill '+(paid?'info':'ok')}>{paid?'PAID · AI':'FREE'}</span></h3>
      <div className="grid" style={{marginTop:8}}>
        <div className={'card '+((report.detailed_depth.risk_breakdown.risk_band==='Critical'||report.detailed_depth.risk_breakdown.risk_band==='High')?'alert':'good')}><div className="ic"><AlertTriangle size={18}/></div><h3>Risk band</h3><b>{report.detailed_depth.risk_breakdown.risk_band}</b><p>weighted risk {report.detailed_depth.risk_breakdown.weighted_risk}</p></div>
        <div className="card"><div className="ic"><ListChecks size={18}/></div><h3>Findings</h3><b>{report.detailed_depth.risk_breakdown.total}</b><p>{Object.entries(report.detailed_depth.risk_breakdown.by_severity||{}).map(([k,v])=>`${v} ${k}`).join(' · ')||'none'}</p></div>
        <div className="card"><div className="ic"><Brain size={18}/></div><h3>AI narrative</h3><b style={{fontSize:14}}>{report.detailed_depth.narrative_source.startsWith('ai')?'AI-generated':'Deterministic'}</b><p>{report.detailed_depth.narrative_source}</p></div>
      </div>
      <div style={{marginTop:12,padding:14,background:'#0d1b2f',borderRadius:12,border:'1px solid #263d5b'}}><b><Brain size={14}/> Executive risk narrative</b><p style={{marginTop:6,lineHeight:1.5}}>{report.detailed_depth.executive_narrative}</p></div>
      <h4 style={{marginTop:16}}>Prioritized remediation roadmap</h4>
      {report.detailed_depth.remediation_roadmap.map((p,i)=><div key={i} className="item"><div className="top"><b>{p.phase}</b><span className="pill mut">{p.count}</span></div>{p.items.map((it,j)=><span key={j} className="sub" style={{display:'block'}}>• {it.title} — <span style={{opacity:0.7}}>{it.action}</span></span>)}</div>)}
      <div className="cols2" style={{marginTop:14}}>
        <div><h4>OWASP coverage</h4>{report.detailed_depth.owasp_coverage.map((o,i)=><div key={i} className="log">{o.category} · <b>{o.findings}</b></div>)}</div>
        <div><h4>Compliance posture</h4>{report.detailed_depth.compliance_posture.map((c,i)=><div key={i} className="log">{c.attention?'⚠️':'✓'} {c.control}</div>)}</div>
      </div>
    </div>;})()}
    {report.browser&&<div className="panel" style={{marginTop:16}}>
      <h3><ScanLine size={16}/> Browser-assisted recon <span className="count">{report.browser.engine}</span></h3>
      <div className="grid" style={{marginTop:8}}>
        <div className="card"><div className="ic"><AlertTriangle size={18}/></div><h3>Browser-only findings</h3><b>{report.browser.browser_only_findings}</b><p>Invisible to HTTP-only scans</p></div>
        <div className="card"><div className="ic"><Code2 size={18}/></div><h3>Rendered surface</h3><b>{report.browser.spa_gap?.rendered_forms??0}f / {report.browser.spa_gap?.rendered_links??0}l</b><p>HTTP saw {report.browser.spa_gap?.raw_forms??0}f / {report.browser.spa_gap?.raw_links??0}l</p></div>
        <div className="card"><div className="ic"><LockKeyhole size={18}/></div><h3>Cookies observed</h3><b>{report.browser.cookies_observed}</b><p>{report.browser.human_takeover?'Human takeover flagged':'Post-JS cookie jar'}</p></div>
      </div>
    </div>}
    <h3>Findings</h3>
    {report.findings.length===0&&<div className="empty">No findings recorded — baseline pass, pending reviewer sign-off.</div>}
    {report.findings.map((f,i)=><div className={'findbox '+f.severity.toLowerCase()} key={i}><b><span className={'sev '+f.severity}>{f.severity}</span>{f.title}</b><p>{f.description}</p><small>{f.remediation} · {Object.values(f.compliance||{}).join(', ')}</small></div>)}
    <div className="cols2">
      <div><h3>AI report intelligence</h3><pre>{JSON.stringify(intel,null,2)}</pre><h3>Enterprise scaffold</h3><pre>{JSON.stringify(enterprise,null,2)}</pre></div>
      <div><h3>Agent tasks</h3>{tasks?.tasks?.map((t,i)=><div className="log" key={i}>{t.status} · {t.module} · {t.summary}</div>)}<h3>Cost events</h3>{tasks?.costs?.map((c,i)=><div className="log" key={i}>${c.estimated_usd} · {c.provider} · {c.operation}</div>)}<h3>Evidence timeline</h3>{timeline?.logs?.map((l,i)=><div className="log" key={i}>{l.created_at} · {l.actor} · {l.action}</div>)}</div>
    </div>
    {report.agent_loop&&<details style={{marginTop:16}}><summary style={{cursor:'pointer',opacity:0.7,padding:'8px 0'}}>▸ Agentic reasoning loop — {report.agent_loop.iterations} steps{report.agent_loop.multi_agent?`, ${report.agent_loop.llm_agents} LLM agents`:''} (how the agents ran)</summary>
      <div className="panel" style={{marginTop:8,border:'1px solid #36d399',background:'linear-gradient(180deg,rgba(54,211,153,0.06),transparent)'}}>
        <div>{report.agent_loop.trace.map((t,i)=><div key={i} className="item" style={{borderLeft:'2px solid '+(t.llm_backed?'#7c5cff':'#36d399')}}><div className="top"><b>#{t.iter} · {t.agent} agent</b>{t.llm_backed&&<span className="pill info">🤖 LLM · {t.llm_source}</span>}<span className="pill mut">{t.decision}</span></div><span className="sub">{t.detail}</span></div>)}</div>
        <h4 style={{marginTop:14}}>🤖 Recommended next actions</h4>
        {report.agent_loop.recommended_actions.map((a,i)=><div key={i} className="item"><div className="top"><b>{a.action}</b><span className={'pill '+(a.priority==='High'?'bad':a.priority==='Medium'?'warn':'mut')}>{a.priority}</span></div><span className="sub">{a.why}</span></div>)}
      </div>
    </details>}
    {report.browser?.screenshot_available&&<div className="panel" style={{marginTop:16}}>
      <h3><ScanLine size={16}/> Rendered page evidence <span className="count">full-page capture</span></h3>
      <p className="sub">Real headless-Chromium screenshot captured during browser recon — visual proof of the assessed surface.</p>
      <div style={{marginTop:12}}><img src={`${API}${report.browser.screenshot_url}`} alt="Rendered homepage evidence" style={{maxWidth:'100%',borderRadius:12,border:'1px solid #263d5b'}}/></div>
    </div>}
  </div></div>;
}

function AccessKeys({keys,onActivate,onRevoke}){
  const k=keys?.keys||[];
  return <div className="view"><div className="panel"><h3>UPI access keys <span className="count">{k.length}</span></h3>
    <div className="hint">Customers scan the UPI QR (Overview → Detailed scan), pay, then you activate their key here after confirming the receipt. Deep audits stay blocked until activated.</div>
    {k.length===0&&<div className="empty">No access keys minted yet.</div>}
    {k.map(x=><div key={x.key} className="item">
      <div className="top"><b><code>{x.key}</code></b>{StatusPill(x.status)}</div>
      <span className="meta">{x.plan} · {x.paid_via} · workspace {x.workspace_id}</span>
      <div className="row" style={{marginTop:8}}>{x.status==='pending'&&<button className="btn" onClick={()=>onActivate(x.key)}>Activate (payment confirmed)</button>}{x.status==='active'&&<button className="btn danger" onClick={()=>onRevoke(x.key)}>Revoke</button>}</div>
    </div>)}
  </div></div>;
}

function RepoAnalyze({repo,setRepo,busy,setBusy,setError}){
  const[path,setPath]=useState('');
  async function run(){
    setBusy(true);setError('');setRepo(null);
    try{const r=await fetch(`${API}/api/repo/analyze`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({repo_path:path,deep:true})});const d=await r.json();if(!r.ok)throw new Error(d.detail||'analysis failed');setRepo(d);}
    catch(e){setError(e.message||'repo analyze failed')}finally{setBusy(false)}
  }
  return <div className="view">
    <div className="hero">
      <span className="eyebrow">Source-code security analysis</span>
      <h2>Scan a repository for secrets and insecure code — cost-efficient by default.</h2>
      <p>Deterministic SAST runs locally at <b>$0</b>. Flip the AI model selector to enrich the summary with one live LLM call only when you choose.</p>
      <div className="row"><input value={path} onChange={e=>setPath(e.target.value)} placeholder="/absolute/path/to/repo (or backend repo)"/><button className="btn" disabled={busy} onClick={run}>{busy?'Scanning…':'Analyze repo'}</button></div>
      <div className="hint">Tip: try <code>/Users/sai/ai-security-agency/backend</code> to scan the platform itself.</div>
    </div>
    {repo&&<>
      <div className="grid">
        <div className="card"><div className="ic"><Code2 size={18}/></div><h3>Files scanned</h3><b>{repo.files_scanned}</b><p>{repo.lines_scanned} lines · {Object.keys(repo.languages||{}).length} languages</p></div>
        <div className={'card '+(repo.security_score<60?'alert':'good')}><div className="ic"><ShieldCheck size={18}/></div><h3>Security score</h3><b>{repo.security_score}/100</b><p>Git commits: {repo.git?.commit_count}</p></div>
        <div className="card good"><div className="ic"><DollarSign size={18}/></div><h3>Analysis cost</h3><b>${repo.cost_usd}</b><p>AI enrichment: ${repo.intelligence?.cost_usd}</p></div>
        <div className="card"><div className="ic"><AlertTriangle size={18}/></div><h3>Issues found</h3><b>{repo.findings?.length||0}</b><p>Critical/High prioritized</p></div>
      </div>
      <div className="panel"><h3>AI summary <span className="count">{repo.intelligence?.mode}</span></h3><p>{repo.intelligence?.summary}</p></div>
      <div className="panel"><h3>Findings <span className="count">{repo.findings?.length||0}</span></h3>
        {(repo.findings||[]).length===0&&<div className="empty">No secrets or insecure patterns detected. Clean baseline.</div>}
        {(repo.findings||[]).map((f,i)=><div key={i} className="item">
          <div className="top"><b><span className={'sev '+f.severity}>{f.severity}</span>{f.rule}</b><Pill kind="info">{f.category}</Pill></div>
          <span className="meta">{f.file}:{f.line}</span>
          <span className="sub">{f.remediation}</span>
        </div>)}
      </div>
    </>}
  </div>;
}

createRoot(document.getElementById('root')).render(<EB><App/></EB>);

