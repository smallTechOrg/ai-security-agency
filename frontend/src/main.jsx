import React,{useEffect,useState}from'react';
import{createRoot}from'react-dom/client';
import{Shield,Activity,FileText,CheckCircle,AlertTriangle,DollarSign,Brain,LockKeyhole,LayoutDashboard,ScanLine,ShieldCheck,Users,ListChecks,ScrollText,CalendarClock,Receipt,Radio,Wrench,ChevronRight,GitBranch,Code2}from'lucide-react';
import'./style.css';
const API=import.meta.env.VITE_API_BASE_URL||'http://127.0.0.1:8011';

class EB extends React.Component{constructor(p){super(p);this.state={e:null}}static getDerivedStateFromError(e){return{e}}componentDidCatch(e){console.error('BOUND ERR',e&&e.message,e&&e.stack)}
  render(){if(this.state.e)return <div className="empty" style={{padding:40}}>View error: {String(this.state.e.message||this.state.e)}</div>;return this.props.children}}

function App(){
  const[view,setView]=useState('overview');
  const[health,setHealth]=useState(null),[dash,setDash]=useState(null),[admin,setAdmin]=useState(null),[domains,setDomains]=useState(null),[auditLog,setAuditLog]=useState(null),[billing,setBilling]=useState(null),[schedules,setSchedules]=useState(null),[tickets,setTickets]=useState(null),[summary,setSummary]=useState(null),[readiness,setReadiness]=useState(null),[users,setUsers]=useState(null),[costGov,setCostGov]=useState(null),[intelModels,setIntelModels]=useState(null),[intelMode,setIntelMode]=useState('deterministic'),[url,setUrl]=useState('https://example.com'),[tier,setTier]=useState('free'),[payment,setPayment]=useState(''),[run,setRun]=useState(null),[report,setReport]=useState(null),[timeline,setTimeline]=useState(null),[tasks,setTasks]=useState(null),[intel,setIntel]=useState(null),[enterprise,setEnterprise]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
  async function api(path,options){const r=await fetch(API+path,options),j=await r.json().catch(()=>({detail:r.statusText}));if(!r.ok)throw new Error(j.detail||`HTTP ${r.status}`);return j}
  async function load(){try{setHealth(await api('/health'));setDash(await api('/api/dashboard'));setAdmin(await api('/api/admin/domain-queue'));setDomains(await api('/api/admin/domains'));setAuditLog(await api('/api/admin/audit-log'));setBilling(await api('/api/billing/plans'));setSchedules(await api('/api/admin/schedules'));setTickets(await api('/api/remediation-tickets'));setSummary(await api('/api/program/summary'));setReadiness(await api('/api/program/readiness'));setUsers(await api('/api/admin/users'));const m=await api('/api/intelligence/models');setIntelModels(m);setIntelMode(m.current)}catch(e){}}
  useEffect(()=>{load()},[]);
  useEffect(()=>{ if(window.gtag) gtag('event','page_view',{page_path:'/'+view}); },[view]);
  function clearReport(){setReport(null);setTimeline(null);setTasks(null);setIntel(null);setEnterprise(null)}
  async function buyDetailed(){setBusy(true);setError('');try{const p=await api('/api/payments/intent',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target_url:url,scan_tier:'detailed'})});setPayment(p.payment_reference);setTier('detailed')}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function start(){setBusy(true);setError('');clearReport();try{const j=await api('/api/bootstrap',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({target_url:url,client_name:'Vanguard Client',workspace_name:'Vanguard Security Program',budget_usd:tier==='detailed'?49:2.0,scan_tier:tier,payment_reference:payment})});setRun(j);setView('scans');await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function openRun(r){const id=r.run_id||r.id;setBusy(true);setError('');setRun({run_id:id,workspace_id:r.workspace_id,asset_id:r.asset_id||0,status:r.status,stage:r.stage,progress:r.progress,app_model:r.app_model||{}});clearReport();try{if(['awaiting_approval','payment_required','queued'].includes(r.status)){if(r.workspace_id)setCostGov(await api(`/api/workspaces/${r.workspace_id}/cost-governor?run_id=${id}`));return;}const [rep,tl,tk,ai,ent,gov]=await Promise.all([api(`/api/runs/${id}/report`),api(`/api/runs/${id}/timeline`),api(`/api/runs/${id}/tasks`),api(`/api/runs/${id}/intelligence`),api(`/api/workspaces/${r.workspace_id}/enterprise`),api(`/api/workspaces/${r.workspace_id}/cost-governor?run_id=${id}`)]);setReport(rep);setTimeline(tl);setTasks(tk);setIntel(ai);setEnterprise(ent);setCostGov(gov);setView('report')}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function approve(){const active=run?.status==='awaiting_approval'?run:dash?.runs?.[0]?.status==='awaiting_approval'?dash.runs[0]:null;if(!active)return setError('Create a free audit or paid detailed scan first; admin approval unlocks testing.');const id=active.run_id||active.id;setBusy(true);setError('');try{await api(`/api/runs/${id}/approve`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin',reason:'Domain ownership and testing scope approved.'})});const executed=await api(`/api/runs/${id}/execute`,{method:'POST'});setRun(executed);const br=await api(`/api/runs/${id}/browser-recon`,{method:'POST'});setRun({...executed,status:br.status,stage:br.stage,progress:br.progress});await api(`/api/workspaces/${active.workspace_id}/enterprise-program`,{method:'POST'});await load();await openRun({...executed,status:br.status,stage:br.stage,progress:br.progress})}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function approveQueueRun(x){setBusy(true);setError('');try{const approved=await api(`/api/admin/domain-queue/${x.run_id}/approve`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({decided_by:'admin',reason:'Domain owner/admin approved from Vanguard queue.'})});setRun(approved);await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function executeQueueRun(x){setBusy(true);setError('');try{const done=await api(`/api/admin/domain-queue/${x.run_id}/execute`,{method:'POST'});await load();await openRun({...done,id:done.run_id})}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function revokeDomain(x){setBusy(true);setError('');try{await api(`/api/admin/domains/${x.asset_id}/revoke`,{method:'POST'});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function enableSchedule(x){setBusy(true);setError('');try{await api(`/api/admin/schedules/${x.workspace_id}/enable`,{method:'POST'});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function closeTicket(t){setBusy(true);setError('');try{await api(`/api/remediation-tickets/${t.id}/status`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({status:'closed'})});await load()}catch(e){setError(e.message)}finally{setBusy(false)}}
  async function pickIntelMode(e){const m=e.target.value;setIntelMode(m);try{await api('/api/intelligence/models',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({mode:m})})}catch(err){setError(err.message)}}

  const newestRun=dash?.runs?.[0],pendingRun=run?.status==='awaiting_approval'?run:(newestRun?.status==='awaiting_approval'?newestRun:null),current=run||newestRun,findings=report?.findings||dash?.findings||[],commerce=dash?.commerce||{};
  const open=tickets?.tickets?.filter(t=>t.status!=='closed').length;
  const nav=[{id:'overview',label:'Overview',icon:LayoutDashboard},{id:'scans',label:'Scans',icon:ScanLine,badge:dash?.runs?.length},{id:'approvals',label:'Domain approvals',icon:ShieldCheck,badge:admin?.items?.filter(x=>x.status==='pending').length},{id:'domains',label:'Domain registry',icon:Radio},{id:'remediation',label:'Remediation',icon:ListChecks,badge:open},{id:'schedules',label:'Schedules',icon:CalendarClock},{id:'team',label:'Team & RBAC',icon:Users},{id:'billing',label:'Billing',icon:Receipt},{id:'audit',label:'Audit log',icon:ScrollText},{id:'readiness',label:'Launch readiness',icon:Wrench},{id:'repo',label:'Repo analysis',icon:Code2}];
  const[repo,setRepo]=useState(null);

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
          {view==='overview'&&<Overview dash={dash} summary={summary} readiness={readiness} costGov={costGov} current={current} pendingRun={pendingRun} tier={tier} setTier={setTier} url={url} setUrl={setUrl} start={start} buyDetailed={buyDetailed} approve={approve} billing={billing} busy={busy} payment={payment} intelModels={intelModels} intelMode={intelMode} pickIntelMode={pickIntelMode}/>}
          {view==='scans'&&<Scans dash={dash} run={run} openRun={openRun} current={current}/>}
          {view==='approvals'&&<Approvals admin={admin} onApprove={approveQueueRun} onExecute={executeQueueRun}/>}
          {view==='domains'&&<Domains domains={domains} onRevoke={revokeDomain}/>}
          {view==='remediation'&&<Remediation tickets={tickets} onClose={closeTicket}/>}
          {view==='schedules'&&<Schedules schedules={schedules} onEnable={enableSchedule}/>}
          {view==='team'&&<Team users={users}/>}
          {view==='billing'&&<Billing billing={billing} summary={summary}/>}
          {view==='audit'&&<AuditLogView log={auditLog}/>}
          {view==='readiness'&&<Readiness readiness={readiness}/>}
          {view==='repo'&&<RepoAnalyze repo={repo} setRepo={setRepo} busy={busy} setBusy={setBusy} setError={setError}/>}
          {view==='report'&&report&&<ReportView report={report} intel={intel} enterprise={enterprise} tasks={tasks} timeline={timeline} costGov={costGov} onClose={()=>setView('scans')}/>}
        </div>
      </div>
    </div>
  );
}

function StatusBar({current}){if(!current)return null;return <div className="statusbar"><Activity size={18} color="#36d399"/><div><b>{current.status}</b><span> · {current.stage}</span></div><div className="prog"><progress max="100" value={current.progress||0}/></div><span>{current.progress||0}%</span></div>}
function Pill({kind,children}){return <span className={'pill '+kind}>{children}</span>}
function StatusPill({s}){const v=s||'unknown';const k={completed:'ok',browser_recon_complete:'ok',report_ready:'ok',approved:'ok',awaiting_approval:'warn',payment_required:'bad',queued:'info',domain_revoked:'bad',cancelled:'bad'}[v]||'mut';return <Pill kind={k}>{String(v).replace(/_/g,' ')}</Pill>}

function Overview({dash,summary,readiness,costGov,current,pendingRun,tier,setTier,url,setUrl,start,buyDetailed,approve,billing,busy,payment}){
  const s=summary?.operations||{}, rev=summary?.commerce||{}, risk=summary?.risk||{}, com=dash?.commerce||{};
  return <div className="view">
    <div className="hero">
      <span className="eyebrow">Enterprise web exposure management</span>
      <h2>Audit a public domain — approvals, budgets, evidence.</h2>
      <p>Start free. Detailed scans are paid and admin-approved before any testing runs.</p>
      <div className="pricing">
        <button className={tier==='free'?'selected':''} onClick={()=>setTier('free')}><b>Free audit</b><span>Headers, TLS, public evidence</span></button>
        <button className={tier==='detailed'?'selected':''} onClick={buyDetailed}><b>Detailed scan · ${com.detailed_scan_price_usd||49}</b><span>Paid intent + admin domain approval</span></button>
      </div>
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

function Remediation({tickets,onClose}){
  const t=tickets?.tickets||[];
  return <div className="view"><div className="panel"><h3>Remediation tickets <span className="count">{t.length}</span></h3>
    {t.length===0&&<div className="empty">No remediation tickets. Run a scan to generate them from findings.</div>}
    {t.map(x=><div key={x.id} className="item">
      <div className="top"><b><span className={'sev '+x.severity}>{x.severity}</span>{x.title}</b>{StatusPill(x.status)}</div>
      <span className="meta">owner {x.owner} · finding #{x.finding_id}</span>
      {x.status!=='closed'&&<button className="btn ghost" onClick={()=>onClose(x)}>Close ticket</button>}
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

function ReportView({report,intel,enterprise,tasks,timeline,costGov,onClose}){
  return <div className="view"><div className="report">
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}><h2><FileText/> Vanguard security report</h2><button className="btn ghost" onClick={onClose}>← Back to scans</button></div>
    <div className="actions"><a href={`${API}/api/runs/${report.run_id}/report.html`} target="_blank">Open HTML report</a><a href={`${API}/api/runs/${report.run_id}/evidence-bundle`} target="_blank">Evidence JSON</a><a href={`${API}/api/client/reports/${report.run_id}`} target="_blank">Client-safe</a><a href={`${API}/api/runs/${report.run_id}/attestation`} target="_blank">Attestation</a></div>
    <div className="score">Security score <b>{report.security_score}</b>/100 · {report.certificate_status}</div>
    <p>{report.executive_summary}</p>
    {costGov&&<div className="hint">Cost governor: {costGov.allowed?'within budget':'over budget'} · remaining ${costGov.remaining_usd} · projected ${costGov.projected_run_cost_usd}</div>}
    <h3>Findings</h3>
    {report.findings.length===0&&<div className="empty">No findings recorded — baseline pass, pending reviewer sign-off.</div>}
    {report.findings.map((f,i)=><div className={'findbox '+f.severity.toLowerCase()} key={i}><b><span className={'sev '+f.severity}>{f.severity}</span>{f.title}</b><p>{f.description}</p><small>{f.remediation} · {Object.values(f.compliance||{}).join(', ')}</small></div>)}
    <div className="cols2">
      <div><h3>AI report intelligence</h3><pre>{JSON.stringify(intel,null,2)}</pre><h3>Enterprise scaffold</h3><pre>{JSON.stringify(enterprise,null,2)}</pre></div>
      <div><h3>Agent tasks</h3>{tasks?.tasks?.map((t,i)=><div className="log" key={i}>{t.status} · {t.module} · {t.summary}</div>)}<h3>Cost events</h3>{tasks?.costs?.map((c,i)=><div className="log" key={i}>${c.estimated_usd} · {c.provider} · {c.operation}</div>)}<h3>Evidence timeline</h3>{timeline?.logs?.map((l,i)=><div className="log" key={i}>{l.created_at} · {l.actor} · {l.action}</div>)}</div>
    </div>
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

