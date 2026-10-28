'use strict';
(() => {
  const API = '/api/v1';
  const state = {token: null, user: null, view: 'overview', search: '', data: {}, authMode: 'login', epoch: 0, busy: false};
  const $ = id => document.getElementById(id);
  function node(tag, attrs = {}, ...children) {
    const element = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'class') element.className = value;
      else if (key.startsWith('on') && typeof value === 'function') element.addEventListener(key.slice(2), value);
      else if (value !== false && value != null) element.setAttribute(key, value === true ? '' : String(value));
    }
    for (const child of children.flat(Infinity)) if (child != null) element.append(child instanceof Node ? child : document.createTextNode(String(child)));
    return element;
  }
  const icon = (name, className='ui-icon') => node('img', {src:`/assets/icons/${name}.svg`,class:className,alt:'','aria-hidden':'true',width:20,height:20});
  const button = (label, handler, type = 'secondary') => node('button', {type: 'button', class: `button ${type}`, onclick: handler}, label);
  const badge = value => node('span', {class: `badge ${['pass','completed','resolved','eligible'].includes(String(value).toLowerCase()) ? 'pass' : ['block','failed','critical','high','blocked'].includes(String(value).toLowerCase()) ? 'block' : ['warn','medium'].includes(String(value).toLowerCase()) ? 'warn' : ['running','queued'].includes(String(value).toLowerCase()) ? 'running' : 'muted'}`}, String(value || '—').replaceAll('_', ' '));
  const date = value => value ? new Date(value).toLocaleString() : '—';
  const short = value => value ? String(value).slice(0, 8) : '—';
  const namedProject = id => (state.data.projects || []).find(p => p.id === id)?.name || short(id);
  function status(message, isError = false) {
    const target = $('app-status');
    if (target) { target.textContent = message; target.className = isError ? 'app-status error' : 'app-status'; target.setAttribute('role', isError ? 'alert' : 'status'); }
  }
  function clearSession(message = '') {
    state.token = null; state.user = null; state.data = {}; state.epoch++; state.search = '';
    $('detail-dialog')?.remove();
    $('app-shell').hidden = true; $('auth-section').hidden = false;
    $('main-content').replaceChildren();
    if ($('global-search')) $('global-search').value = '';
    $('auth-password').value = '';
    $('auth-error').textContent = message;
  }
  async function api(path, options = {}) {
    const headers = {...(state.token ? {Authorization: `Bearer ${state.token}`} : {}), ...options.headers};
    if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
    const response = await fetch(API + path, {...options, credentials: 'same-origin', headers});
    let data = null;
    if (response.status !== 204) { try { data = await response.json(); } catch { throw new Error('The server returned an unreadable response. Please retry.'); } }
    if (!response.ok) {
      if (response.status === 401 && state.user) clearSession('Your session expired. Sign in again.');
      const detail = data?.detail;
      throw new Error(typeof detail === 'string' ? detail : Array.isArray(detail) ? detail.map(e => `${e.loc?.slice(1).join('.') || 'Input'}: ${e.msg}`).join('; ') : `Request failed (${response.status}). Please retry.`);
    }
    return data;
  }
  const post = (path, data) => api(path, {method: 'POST', body: JSON.stringify(data)});
  async function action(control, task) {
    if (control) control.disabled = true;
    status('Working…');
    try { await task(); } catch (error) { status(error.message, true); }
    finally { if (control?.isConnected) control.disabled = false; }
  }
  async function load(renderAfter = true) {
    const epoch = state.epoch;
    const endpoints = {dashboard: '/dashboard', projects: '/projects?limit=1000', repositories: '/repositories?limit=1000', scans: '/scans', findings: '/findings', policies: '/policies', audit: '/audit-logs', reports: '/reports'};
    const entries = await Promise.all(Object.entries(endpoints).map(async ([key, path]) => [key, await api(path)]));
    if (!state.user || epoch !== state.epoch) return;
    state.data = Object.fromEntries(entries);
    if (renderAfter) render();
  }
  function matches(item) { return !state.search || (JSON.stringify(item) + ' ' + (item.project_id ? namedProject(item.project_id) : '')).toLowerCase().includes(state.search); }
  function panel(title, subtitle, body, extraClass = '') {
    return node('section', {class: `panel ${extraClass}`}, node('div', {class: 'panel-header'}, node('div', {}, node('h2', {class: 'panel-title'}, title), subtitle && node('p', {class: 'panel-subtitle'}, subtitle))), body);
  }
  function empty(title, description, control) {
    return node('div', {class: 'empty-state'}, node('div', {class: 'empty-icon', 'aria-hidden': 'true'}, icon('folder')), node('h3', {}, title), node('p', {}, description), control);
  }
  function table(headers, rows, emptyTitle = 'No results', emptyDescription = 'New activity will appear here.') {
    if (!rows.length) return empty(emptyTitle, emptyDescription);
    return node('div', {class: 'table-wrap'}, node('table', {}, node('thead', {}, node('tr', {}, headers.map(h => node('th', {scope: 'col'}, h)))), node('tbody', {}, rows.map(row => node('tr', {}, row.map(cell => node('td', {}, cell)))))));
  }
  function navigate(view) { state.view = view; state.search = ''; if ($('global-search')) $('global-search').value = ''; render(); }
  function hero(title, subtitle, actions = []) {
    const split=title.lastIndexOf(' ');const lead=split<0?'':title.slice(0,split+1);const accent=split<0?title:title.slice(split+1);
    return node('section', {class: 'hero'}, node('div', {class: 'hero-copy'}, node('p', {class: 'eyebrow hero-kicker'}, state.view === 'overview' ? 'SECURITY OVERVIEW' : 'SENTINELX / ' + state.view.toUpperCase()), node('h1', {class:'hero-title'},lead,node('em',{class:'hero-accent'},accent)), node('p', {class:'hero-description'}, subtitle)), node('div', {class: 'hero-actions'}, actions));
  }
  function coverageNotice() { return node('div', {class: 'coverage-notice'}, node('strong', {}, 'Baseline analysis · release protection active'), node('p', {}, 'Secret patterns, selected Python rules and IaC checks run on the backend. SCA, container image scanning and DAST are not configured. Releases remain blocked while coverage is incomplete.')); }
  function scanRows(scans) {
    return scans.map(scan => [node('span', {class: 'mono'}, short(scan.id)), namedProject(scan.project_id), scan.source === 'github' ? 'GitHub' : 'ZIP upload', scan.branch || '—', badge(scan.status), badge(scan.decision), scan.risk_score ?? '—', date(scan.created_at), node('div', {class: 'row-actions'}, button('Details', () => showScan(scan.id), 'ghost'), ['completed','failed'].includes(scan.status) ? button('View report', () => openReport(scan.id), 'ghost') : null)]);
  }
  function severityDistribution(counts = {}) {
    const levels=['critical','high','medium','low','informational'];
    const values=levels.map(level=>Math.max(0,Number(counts[level])||0));
    const total=values.reduce((sum,value)=>sum+value,0);
    const chart=document.createElementNS('http://www.w3.org/2000/svg','svg');
    chart.setAttribute('viewBox','0 0 100 12');chart.setAttribute('preserveAspectRatio','none');chart.setAttribute('class','severity-track');chart.setAttribute('role','img');
    chart.setAttribute('aria-label',`Open finding severity: ${levels.map((level,index)=>`${values[index]} ${level}`).join(', ')}`);
    let offset=0;
    if(!total){const rect=document.createElementNS(chart.namespaceURI,'rect');rect.setAttribute('width','100');rect.setAttribute('height','12');rect.setAttribute('class','severity-segment empty');chart.append(rect);}
    levels.forEach((level,index)=>{if(!values[index]||!total)return;const rect=document.createElementNS(chart.namespaceURI,'rect');const width=values[index]/total*100;rect.setAttribute('x',String(offset));rect.setAttribute('width',String(width));rect.setAttribute('height','12');rect.setAttribute('class',`severity-segment ${level}`);chart.append(rect);offset+=width;});
    return node('section',{class:'severity-distribution',id:'severity-distribution','aria-labelledby':'severity-title'},node('div',{class:'severity-heading'},node('h3',{id:'severity-title'},'Finding severity'),node('span',{},`${total} open findings`)),chart,node('div',{class:'severity-legend'},levels.map((level,index)=>node('div',{class:'severity-legend-item'},node('span',{class:`severity-dot ${level}`,'aria-hidden':'true'}),node('span',{},level[0].toUpperCase()+level.slice(1)),node('strong',{},values[index])))),total ? null : node('p',{class:'panel-subtitle'},'No open findings recorded. Run a scan to assess your repository; missing coverage still blocks releases.'));
  }
  function scanJourney() {
    return node('div',{class:'workflow-guide','aria-label':'Scan workflow'},[['01','Connect your source','Add a public GitHub repository or upload a ZIP.'],['02','Run backend analysis','Track actual scanner execution in Security scans.'],['03','Read your report','Review severity, affected locations and remediation.']].map(([step,title,description])=>node('div',{class:'workflow-step'},node('span',{class:'step-index'},step),node('div',{class:'workflow-copy'},node('strong',{},title),node('p',{},description)))));
  }
  function inlineMetrics(metrics) {
    return node('div',{class:'overview-metrics'},metrics.map(([symbol,label,value,footer])=>node('article',{class:'overview-metric metric-card'},icon(symbol,'metric-inline-icon'),node('div',{},node('p',{class:'metric-inline-label metric-label'},label),node('strong',{class:'metric-inline-value metric-value'},value),node('p',{class:'metric-inline-footer metric-footer'},footer)))));
  }
  function overviewActivity() {
    const severityOrder=['critical','high','medium','low','informational'];
    const rows=state.data.repositories.map(repo=>({repo,scan:state.data.scans.find(scan=>scan.repository_id===repo.id)}));
    const zipProjects=new Set();
    for(const scan of state.data.scans){if(scan.source==='zip'&&!zipProjects.has(scan.project_id)){zipProjects.add(scan.project_id);rows.push({scan});}}
    rows.sort((a,b)=>String(b.scan?.created_at||b.repo?.created_at||'').localeCompare(String(a.scan?.created_at||a.repo?.created_at||'')));
    return table(['Repository','Source','Branch','Last scan','Findings','Highest severity','Result'],rows.filter(({repo,scan})=>matches(scan||repo)).slice(0,5).map(({repo,scan})=>{
      const highest=severityOrder.find(level=>scan?.findings?.some(f=>f.severity===level));
      return [node('div',{class:'repository-name'},icon(repo?'brand-github':'file-zip'),node('strong',{},repo?repo.url.replace('https://github.com/',''):namedProject(scan.project_id))),repo?'GitHub':'ZIP',node('span',{class:'branch-name'},icon('git-branch'),repo?.branch||scan?.branch||'—'),badge(scan?.status||'NOT_SCANNED'),scan?.findings?.length??'—',highest?badge(highest):node('span',{class:'muted'},scan?.status==='completed'?'None detected':'—'),node('div',{class:'row-actions'},scan?(['completed','failed'].includes(scan.status)?button('View report',()=>openReport(scan.id),'ghost'):button('Details',()=>showScan(scan.id),'ghost')):button('Start scan',event=>startRepositoryScan(repo.id,event.currentTarget),'ghost'))];
    }),'No repository scans yet','Connect a repository and start a scan to see real findings and reports.');
  }
  function riskGauge(scan) {
    const available=scan?.status==='completed'&&Number.isFinite(Number(scan.risk_score));
    const value=available?Math.max(0,Math.min(100,Number(scan.risk_score))):null;
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 240 130');svg.setAttribute('class','risk-gauge');svg.setAttribute('aria-hidden','true');
    for(const cls of ['risk-track','risk-fill']){const path=document.createElementNS(svg.namespaceURI,'path');path.setAttribute('d','M 20 120 A 100 100 0 0 1 220 120');path.setAttribute('pathLength','100');path.setAttribute('class',cls+(cls==='risk-fill'?' risk-gauge-value':' risk-gauge-track'));if(cls==='risk-fill')path.setAttribute('stroke-dasharray',`${value??0} 100`);svg.append(path);}
    return node('div',{class:'risk-overview'},svg,node('div',{class:'risk-label'},node('strong',{class:'risk-value'},value??'—'),node('span',{},'/ 100 observed risk')),available?node('meter',{class:'risk-meter',min:0,max:100,value,'aria-label':'Latest completed scan observed risk'},value):null);
  }
  function renderOverview(root) {
    const d=state.data.dashboard;
    const latest=state.data.scans.find(scan=>scan.completed_at);
    const connect=button('Connect repository',()=>navigate('repositories'),'primary');connect.prepend(icon('git-branch'));
    root.append(hero('Understand your repository risk.','Connect your repositories, scan for security issues, and read detailed reports — all in one place.',[connect]));
    root.append(inlineMetrics([['folder','Projects',d.projects,'Connected applications'],['search','Total scans',d.total_scans,'Across all repositories'],['file-report','Open findings',d.open_findings,'Awaiting investigation'],['ban','Blocked releases',d.blocked_releases,'Deployment evaluations']]));
    root.append(panel('Findings by severity','Open security findings across your saved scans.',severityDistribution(d.severity_counts),'severity-panel'));
    const activity=panel('Repository scan activity','Latest scan results from your connected repositories.',overviewActivity(),'repository-activity');
    activity.querySelector('.panel-header').append(button('View all repositories',()=>navigate('repositories'),'ghost'));
    const scanned=new Set(state.data.scans.filter(scan=>scan.repository_id&&scan.status==='completed').map(scan=>scan.repository_id)).size;
    const summary=node('div',{class:'release-summary-content'},riskGauge(latest),node('div',{class:'release-verdict'},badge(latest?.decision||'NOT_EVALUATED')),node('p',{class:'release-description'},latest?latest.status==='failed'?'Scan execution failed. Review the report before making a release decision.':latest.decision==='BLOCK'?'Blocking findings or incomplete engine coverage require attention before release.':'Decision applies to the recorded scan and policy snapshot.':'Run your first scan to evaluate repository risk.'),node('div',{class:'release-meta'},node('div',{},icon('file-report'),node('span',{},'Latest scan'),node('strong',{},latest?.status||'Not run')),node('div',{},icon('stack'),node('span',{},'Repositories scanned'),node('strong',{},`${scanned} of ${state.data.repositories.length}`))),node('div',{class:'release-notice'},icon('alert-circle'),node('div',{},node('strong',{},'Scanner coverage incomplete'),node('p',{},'SCA, container image scanning and DAST are not configured. Required coverage remains blocked.'))),latest?button('View latest report',()=>openReport(latest.id),'ghost'):button('Start your first scan',()=>navigate('repositories'),'ghost'));
    root.append(node('div',{class:'overview-content'},activity,panel('Release summary','Latest recorded scan and required coverage.',summary,'release-summary')));
    const gates=[{scanner:'secrets',status:'NOT_RUN'},{scanner:'sast',status:'NOT_RUN'},{scanner:'iac',status:'NOT_RUN'},{scanner:'sca',status:'NOT_CONFIGURED'},{scanner:'container',status:'NOT_CONFIGURED'},{scanner:'dast',status:'NOT_CONFIGURED'}].map(fallback=>latest?.gates?.find(gate=>gate.scanner===fallback.scanner)||fallback);
    if(latest?.gates?.some(gate=>gate.scanner==='runtime'))gates.push(latest.gates.find(gate=>gate.scanner==='runtime'));
    const names={runtime:['code','PHP runtime'],secrets:['shield-lock','Secrets'],sast:['code','SAST'],iac:['cube','IaC'],sca:['database','SCA'],container:['brand-docker','Container'],dast:['target','DAST']};
    root.append(panel('Security engine execution','Latest execution status from your recorded scan.',node('div',{class:'engine-strip'},gates.map(gate=>{const [symbol,label]=names[gate.scanner]||['settings',gate.scanner||gate.name];return node('div',{class:'engine-item'},icon(symbol,'engine-icon'),node('div',{},node('strong',{class:'engine-name'},label),badge(gate.status)));})),'engine-panel'));
  }
  function field(label, input) { return node('label', {class: 'field'}, node('span', {}, label), input); }
  const input = (id, attrs = {}) => node('input', {id, name: id, ...attrs});
  function createProjectForm() {
    const form = node('form', {id: 'project-form', class:'form-grid'}, field('Name', input('new-project-name', {required:true,maxlength:120,placeholder:'Payments API'})), node('button', {class:'button secondary',type:'submit'}, 'Create project'));
    form.addEventListener('submit', event => { event.preventDefault(); action(form.querySelector('button'), async () => { const name=$('new-project-name').value.trim();if(!name)throw new Error('Project name cannot be blank.');const item = await post('/projects', {name}); await load(); status(`Project ${item.name} created. You can now select it for a ZIP scan.`); }); });
    return form;
  }
  function canManageSources() {return ['admin','security_analyst','developer'].includes(state.user?.role);}
  function environments(selected='development',id='edit-project-environment') {return node('select',{id,required:true},['development','staging','production'].map(value=>node('option',{value,selected:value===selected},value)));}
  async function dialogSubmit(form, task) {
    const submit=form.querySelector('button[type="submit"]');
    let error=form.querySelector('.form-error');
    if(!error){error=node('p',{class:'form-error',role:'alert'});form.append(error);}
    error.textContent='';submit.disabled=true;
    try{await task();}catch(failure){if(form.isConnected){error.textContent=failure.message;error.focus();}else status(failure.message,true);}
    finally{if(submit.isConnected)submit.disabled=false;}
  }
  function sourceUrl(url) {
    let parsed;try{parsed=new URL(url);}catch{throw new Error('Enter a valid GitHub repository URL.');}
    if(parsed.protocol!=='https:'||parsed.hostname!=='github.com'||parsed.username||parsed.password||parsed.port||parsed.search||parsed.hash||!/^\/[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+\/?$/.test(parsed.pathname))throw new Error('Use https://github.com/owner/repository. Private repositories are not supported yet.');
    return url;
  }
  async function viewProject(id) {await action(null,async()=>{
    const item=await api(`/projects/${encodeURIComponent(id)}`);
    const repos=state.data.repositories.filter(repo=>repo.project_id===id);const scans=state.data.scans.filter(scan=>scan.project_id===id);
    const content=node('div',{},node('h3',{},item.name),node('p',{},item.description||'No description provided.'),table(['Environment','Technology','Repositories','Scans','Created'],[[item.environment,item.technology||'Not specified',repos.length,scans.length,date(item.created_at)]]),node('h3',{},'Connected repositories'),table(['Repository','Branch'],repos.map(repo=>[repo.url,repo.branch]),'No repositories connected','Connect a repository or upload source to begin analysis.'));
    const controls=canManageSources()?[button('Edit project',()=>editProject(id),'primary'),button('Delete project',()=>confirmSourceDelete('project',item),'ghost')]:[];
    dialog('Project details',content,controls);status('Project details loaded.');
  });}
  async function editProject(id) {await action(null,async()=>{
    const item=await api(`/projects/${encodeURIComponent(id)}`);
    const name=input('edit-project-name',{value:item.name,required:true,maxlength:120});const description=node('textarea',{id:'edit-project-description',maxlength:2000},item.description||'');const technology=input('edit-project-technology',{value:item.technology||'',maxlength:120});const environment=environments(item.environment);
    const form=node('form',{id:'edit-project-form',class:'form-grid'},field('Project name',name),field('Description',description),field('Technology',technology),field('Environment',environment),node('p',{class:'panel-subtitle'},'Updates project metadata. Existing scan reports retain their recorded findings and decisions.'),node('button',{type:'submit',class:'button primary'},'Save project'));
    form.addEventListener('submit',event=>{event.preventDefault();dialogSubmit(form,async()=>{if(!name.value.trim())throw new Error('Project name cannot be blank.');await api(`/projects/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({name:name.value.trim(),description:description.value,technology:technology.value.trim(),environment:environment.value})});closeDialog();await load();status('Project updated.');});});
    dialog('Edit project',form);
  });}
  async function viewRepository(id) {await action(null,async()=>{
    const item=await api(`/repositories/${encodeURIComponent(id)}`);const scans=state.data.scans.filter(scan=>scan.repository_id===id);
    const content=node('div',{},node('h3',{},item.url),node('p',{},'A configured source is not proof of successful GitHub access. Start a scan to verify access and analyze the repository.'),table(['Project','Branch','Provider','Created'],[[namedProject(item.project_id),item.branch,item.provider||'github',date(item.created_at)]]),node('h3',{},'Recorded scans'),table(['Scan','Execution','Decision','Started'],scans.map(scan=>[short(scan.id),badge(scan.status),badge(scan.decision),date(scan.created_at)]),'No scans yet','Start a scan to generate findings and a security report.'));
    const controls=canManageSources()?[button('Edit repository',()=>editRepository(id),'primary'),button('Disconnect repository',()=>confirmSourceDelete('repository',item),'ghost')]:[];
    dialog('Repository details',content,controls);status('Repository details loaded.');
  });}
  async function editRepository(id) {await action(null,async()=>{
    const item=await api(`/repositories/${encodeURIComponent(id)}`);
    const project=node('select',{id:'edit-repository-project',required:true},state.data.projects.map(p=>node('option',{value:p.id,selected:p.id===item.project_id},p.name)));
    const url=input('edit-repository-url',{type:'url',value:item.url,required:true,maxlength:300});const branch=input('edit-repository-branch',{value:item.branch,required:true,maxlength:128});
    const form=node('form',{id:'edit-repository-form',class:'form-grid'},field('Project',project),field('Repository URL',url),field('Branch',branch),node('p',{class:'panel-subtitle'},'Changes apply to future scans. Historical scans keep their recorded source and project. Repositories with active scans cannot be edited.'),node('button',{type:'submit',class:'button primary'},'Save repository'));
    form.addEventListener('submit',event=>{event.preventDefault();dialogSubmit(form,async()=>{const value=sourceUrl(url.value.trim());if(!branch.value.trim())throw new Error('Branch cannot be blank.');await api(`/repositories/${encodeURIComponent(id)}`,{method:'PUT',body:JSON.stringify({project_id:project.value,url:value,branch:branch.value.trim()})});closeDialog();await load();status('Repository updated. Future scans use the new configuration.');});});
    dialog('Edit repository',form);
  });}
  function confirmSourceDelete(kind,item) {
    const project=kind==='project';const label=project?'Delete project':'Disconnect repository';
    const confirm=input('confirm-delete',{type:'checkbox',required:true});const submit=node('button',{type:'submit',class:'button primary',disabled:true},label);
    const form=node('form',{id:project?'delete-project-form':'disconnect-repository-form',class:'form-grid'},node('h3',{},item.name||item.url),node('p',{class:'error'},project?'This permanently deletes this project, its connected repositories, scans, findings, deployment records and generated report history. Audit logs are retained.':'This disconnects the repository and prevents new scans from this connection. Historical scans, findings and reports are retained.'),node('p',{class:'panel-subtitle'},'An active scan must finish before this operation can proceed.'),node('label',{class:'checkbox-field'},confirm,'I understand and confirm'),submit);
    confirm.addEventListener('change',()=>submit.disabled=!confirm.checked);
    form.addEventListener('submit',event=>{event.preventDefault();if(!confirm.checked)return;dialogSubmit(form,async()=>{await api(`/${project?'projects':'repositories'}/${encodeURIComponent(item.id)}?confirm=true`,{method:'DELETE'});closeDialog();await load();status(project?'Project and associated scan history deleted. Audit logs retained.':'Repository disconnected. Historical scans, findings and reports retained.');});});
    dialog(label,form);
  }
  function renderRepositories(root) {
    root.append(hero('Bring your code into focus.', 'Connect a public GitHub repository or upload an authorized project ZIP.'),scanJourney());
    root.append(panel('Projects','Manage application metadata and inspect connected source history.',table(['Project','Environment','Technology','Created','Actions'],state.data.projects.filter(matches).map(item=>[item.name,badge(item.environment),item.technology||'—',date(item.created_at),node('div',{class:'row-actions'},button('View project',()=>viewProject(item.id),'ghost'),canManageSources()?[button('Edit project',()=>editProject(item.id),'ghost'),button('Delete project',()=>confirmSourceDelete('project',item),'ghost')]:null)]),'No projects yet','Create a project below, or connect a repository to create one.')));
    root.append(panel('Connected repositories', 'Public GitHub access · connecting configures a source; scanning verifies archive access.', table(['Repository','Project','Branch','Source status','Actions'], state.data.repositories.filter(matches).map(repo => [node('span', {class:'mono'}, repo.url), namedProject(repo.project_id), repo.branch, badge('configured'),node('div',{class:'row-actions'},button('View repository',()=>viewRepository(repo.id),'ghost'),canManageSources()?[button('Start scan', event => startRepositoryScan(repo.id, event.currentTarget), 'primary'),button('Edit repository',()=>editRepository(repo.id),'ghost'),button('Disconnect repository',()=>confirmSourceDelete('repository',repo),'ghost')]:null)]), 'No repositories connected', 'Use the form below to connect your first repository.')));
    if(!canManageSources()){root.append(node('p',{class:'panel-subtitle'},'Read-only access. A workspace writer can create or change source configuration.'));return;}
    const connect = node('form', {id:'connect-form',class:'form-grid'}, field('Project name', input('project-name',{required:true,maxlength:120,placeholder:'My application'})), field('Repository URL',input('repo-url',{required:true,type:'url',placeholder:'https://github.com/owner/repository'})), field('Branch',input('repo-branch',{required:true,value:'main',maxlength:128})), node('label',{class:'checkbox-field'},input('scan-on-connect',{type:'checkbox',checked:true}), 'Start a scan after connecting'), node('button',{class:'button primary',type:'submit'},'Connect repository'));
    connect.addEventListener('submit', event => { event.preventDefault(); action(connect.querySelector('button'), async () => {
      const name=$('project-name').value.trim(), url=$('repo-url').value.trim(), branch=$('repo-branch').value.trim(), scanNow=$('scan-on-connect').checked;
      sourceUrl(url);if(!name)throw new Error('Project name cannot be blank.');
      let project=state.data.projects.find(p=>p.name===name);
      if (!project) { project=await post('/projects',{name}); state.data.projects.unshift(project); }
      const repo=await post('/repositories',{project_id:project.id,url,branch});
      if (scanNow) { await post('/scans',{repository_id:repo.id}); state.view='scans'; }
      await load(); status(scanNow ? 'Repository connected. Scan queued; results update automatically.' : 'Repository connected. Start a scan to verify access and analyze its contents.');
    }); });
    const projects = state.data.projects;
    const select = node('select',{id:'upload-project',required:true},node('option',{value:''},'Select a project'),projects.map(p=>node('option',{value:p.id},p.name)));
    const upload = node('form',{id:'upload-form',class:'form-grid'},field('Project',select),field('Project ZIP',input('upload-file',{type:'file',accept:'.zip,application/zip',required:true})),node('p',{class:'panel-subtitle'},'Up to 20 MiB compressed. Archive contents are never executed.'),node('button',{type:'submit',class:'button primary',disabled:!projects.length},'Upload and scan'));
    upload.addEventListener('submit',event=>{event.preventDefault();action(upload.querySelector('button'),async()=>{
      const file=$('upload-file').files[0]; if(!file) throw new Error('Select a ZIP archive.'); if(file.size>20*1024*1024) throw new Error('ZIP uploads must be at most 20 MiB.');
      const body=new FormData();body.append('file',file);await api(`/projects/${encodeURIComponent($('upload-project').value)}/upload`,{method:'POST',body});state.view='scans';await load();status('ZIP uploaded. Analysis queued; results update automatically.');
    });});
    root.append(node('div',{class:'dashboard-grid'},panel('Connect GitHub','Only scan repositories you own or are authorized to assess.',connect),panel('Upload a project','Create a project first, then upload its source archive.',node('div',{},upload,createProjectForm()))));
    root.append(coverageNotice());
  }
  async function startRepositoryScan(id, control) { await action(control,async()=>{await post('/scans',{repository_id:id});state.view='scans';await load();status('Security scan queued. Results update automatically.');}); }
  function renderScans(root) {
    const ready=state.data.scans.find(scan=>['completed','failed'].includes(scan.status));
    root.append(hero('Follow every security decision.', 'Execution status and release decisions are shown separately.',[button('New scan',()=>navigate('repositories'),'primary'),ready?button('View latest report',()=>openReport(ready.id)):null]));
    root.append(panel('All scans','Queued and running scans refresh automatically.',table(['Scan','Project','Source','Branch','Execution','Decision','Risk','Started','Actions'],scanRows(state.data.scans.filter(matches)),'No scans found','Connect a repository or upload a ZIP to begin.')));root.append(coverageNotice());
  }
  function findingDetails(finding) {
    return node('article',{class:'finding-detail'},node('h3',{},finding.title),node('div',{class:'row-actions'},badge(finding.severity),badge(finding.scanner),badge(finding.status)),node('p',{class:'mono'},`${finding.path || '—'}${finding.line ? ':'+finding.line : ''}`),node('h4',{},'Description'),node('p',{},finding.description || 'No description provided.'),node('h4',{},'Remediation'),node('p',{},finding.remediation || 'Review this finding with your security team.'),finding.cwe && node('p',{},finding.cwe));
  }
  function showFinding(finding) {
    const content=node('div',{},findingDetails(finding));
    if(['admin','security_analyst'].includes(state.user.role)) {
      const select=node('select',{id:'finding-status'},['open','resolved','ignored'].map(v=>node('option',{value:v,selected:v===finding.status},v)));
      const form=node('form',{class:'form-grid'},field('Review status',select),field('Review reason',node('textarea',{id:'finding-reason',minlength:3,maxlength:2000,required:true})),node('button',{type:'submit',class:'button primary'},'Save review'),node('p',{class:'panel-subtitle'},'Review status does not rewrite the original scan decision. Rescan to evaluate a release.'));
      form.addEventListener('submit',e=>{e.preventDefault();action(form.querySelector('button'),async()=>{await api(`/findings/${encodeURIComponent(finding.id)}`,{method:'PATCH',body:JSON.stringify({status:select.value,reason:$('finding-reason').value})});closeDialog();await load();status('Finding review saved. Original scan decision preserved.');});});content.append(form);
    }
    dialog('Finding details',content);
  }
  function renderFindings(root) {
    root.append(hero('Turn findings into action.', 'Investigate detections, review their context and track remediation.'));
    const select=node('select',{'aria-label':'Filter by severity',id:'severity-filter'},node('option',{value:''},'All severities'),['critical','high','medium','low','informational'].map(s=>node('option',{value:s},s)));
    const holder=node('div');const draw=()=>holder.replaceChildren(table(['Finding','Severity','Engine','Project','Location','Status','Actions'],state.data.findings.filter(matches).filter(f=>!select.value||f.severity===select.value).map(f=>[f.title,badge(f.severity),f.scanner,namedProject(f.project_id),node('span',{class:'mono'},`${f.path||'—'}:${f.line||'—'}`),badge(f.status),button('Inspect',()=>showFinding(f),'ghost')]),'No findings found','Run a scan or adjust your filters. An empty list alone does not certify security.'));
    select.addEventListener('change',draw);draw();root.append(node('div',{class:'toolbar'},select),holder);
  }
  let lastFocused = null;
  function closeDialog(){const current=$('detail-dialog');if(current){current.close();current.remove();}lastFocused?.focus();}
  function dialog(title,content,actions=[]) {
    closeDialog();lastFocused=document.activeElement;
    const d=node('dialog',{id:'detail-dialog',class:'modal-card edition-modal','aria-labelledby':'detail-title'},node('div',{class:'panel-header'},node('h2',{id:'detail-title'},title),button('Close',closeDialog,'ghost')),content,node('div',{class:'hero-actions'},actions));
    d.addEventListener('cancel',e=>{e.preventDefault();closeDialog();});document.body.append(d);d.showModal();
  }
  function gateTable(gates=[]) {return table(['Engine','Tool','Status','Findings','Duration'],gates.map(g=>[String(g.scanner||g.name||'—').toUpperCase(),g.tool||'—',badge(g.status),g.findings??0,g.duration_ms==null?'—':`${g.duration_ms} ms`]),'No gate results','The scan has not produced engine results.');}
  async function showScan(id) {await action(null,async()=>{
    const scan=await api(`/scans/${encodeURIComponent(id)}`);
    const controls=[];
    if(scan.repository_id) controls.push(button('Re-run scan',e=>action(e.currentTarget,async()=>{await post(`/scans/${encodeURIComponent(id)}/rerun`,{});closeDialog();await load();status('Scan queued again.');}),'primary'));
    if(['completed','failed'].includes(scan.status))controls.push(button('View report',()=>openReport(id)));
    dialog('Scan details',node('div',{},node('p',{class:'mono'},scan.id),node('div',{class:'row-actions'},badge(scan.status),badge(scan.decision)),node('p',{},`Project: ${namedProject(scan.project_id)} · Source: ${scan.source} · Branch: ${scan.branch||'—'}`),node('p',{},`Started: ${date(scan.started_at)} · Completed: ${date(scan.completed_at)}`),scan.error&&node('p',{class:'error'},scan.error),gateTable(scan.gates),node('p',{},scan.coverage?.complete===true?'Required coverage complete.':'Required coverage is incomplete; release is blocked.'),node('ul',{},(scan.reasons||[]).map(r=>node('li',{},r)))),controls);
  });}
  function downloadReport(report) {
    const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=node('a',{href:url,download:`sentinelx-report-${report.scan.id}.json`});document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);status('JSON report downloaded.');
  }
  async function openReport(id){await action(null,async()=>{
    const report=await api(`/scans/${encodeURIComponent(id)}/report`);const scan=report.scan;
    const content=node('div',{class:'report-content'},node('p',{class:'eyebrow'},'SECURITY SCAN REPORT'),node('h2',{},report.project.name),node('p',{},`Generated ${date(report.generated_at)} · Report ${report.report_version}`),node('div',{class:'report-summary'},badge(scan.decision),node('strong',{},`Observed risk ${scan.risk_score??'—'} / 100`),node('span',{},`${(scan.findings||[]).length} findings`)),node('p',{class:'mono'},`Scan ${scan.id}`),node('p',{},`Source: ${scan.source} · Branch: ${scan.branch||'—'} · Commit: ${scan.commit||'Not resolved; branch archive scanned'}`),node('h3',{},'Release decision'),node('p',{},report.deployment_allowed?'Eligible under the evaluated policy. No deployment was executed.':'Deployment blocked. Resolve blocking findings and incomplete scanner coverage before release.'),scan.error&&node('p',{class:'error'},scan.error),node('ul',{},(scan.reasons||[]).map(r=>node('li',{},r))),node('h3',{},'Security gates'),gateTable(scan.gates),node('h3',{},'Coverage and limitations'),node('p',{},scan.coverage?.complete===true?'Required coverage complete.':'Incomplete coverage. This report is a baseline assessment, not a security certification.'),node('ul',{},[...(scan.coverage?.limitations||[]),...(report.limitations||[])].map(r=>node('li',{},r))),node('h3',{},'Findings and remediation'),(scan.findings||[]).length?(scan.findings||[]).map(f=>node('details',{},node('summary',{},badge(f.severity),' ',f.title),findingDetails(f))):node('p',{},'No findings were detected by the engines that ran. Review coverage before drawing conclusions.'));
    dialog('Security report',content,[button('Download JSON',()=>downloadReport(report),'primary'),button('Print report',()=>{content.querySelectorAll('details').forEach(d=>d.open=true);window.print();})]);status('Report generated from actual scan results.');
  });}
  function renderReports(root){root.append(hero('Evidence for every release.', 'Read security gates, findings and remediation guidance from completed scans.'));root.append(panel('Security reports','Generated on demand from recorded scan results.',table(['Project','Scan','Decision','Risk','Completed','Actions'],state.data.reports.filter(matches).map(r=>[namedProject(r.project_id),node('span',{class:'mono'},short(r.scan_id)),badge(r.decision),r.risk_score??'—',date(r.completed_at),button('View report',()=>openReport(r.scan_id),'primary')]),'No reports yet','A completed or failed scan produces a report.')));}
  function renderPolicies(root){root.append(hero('Make release rules explicit.', 'Severity rules apply to findings. Failed and unavailable required engines always block releases.'));
    for(const policy of state.data.policies.filter(matches)){
      const fields={};const form=node('form',{class:'form-grid'});for(const key of ['critical','high','medium','low','informational','scanner_failure']){const control=node('select',{'aria-label':key.replace('_',' ')},(key==='scanner_failure'?['BLOCK','WARN']:['BLOCK','WARN','ALLOW']).map(value=>node('option',{value,selected:policy[key]===value},value)));fields[key]=control;form.append(field(key.replaceAll('_',' '),control));}
      if(['admin','security_analyst'].includes(state.user.role)){const submit=node('button',{type:'submit',class:'button primary'},'Save policy');form.append(submit);form.addEventListener('submit',event=>{event.preventDefault();action(submit,async()=>{const body={name:policy.name};for(const [key,control]of Object.entries(fields))body[key]=control.value;await api(`/policies/${encodeURIComponent(policy.id)}`,{method:'PUT',body:JSON.stringify(body)});await load();status('Policy saved. New scans use the updated rules; existing reports retain their policy snapshot.');});});}else form.querySelectorAll('select').forEach(s=>s.disabled=true);
      root.append(panel(policy.name,'Applies to new scans. Scanner failure remains a fail-closed release condition.',form));
    }
    root.append(coverageNotice());
  }
  function renderAudit(root){root.append(hero('A record of important actions.', 'Account activity, source connections, scan decisions and finding reviews.'));root.append(panel('Audit trail','Most recent 100 recorded actions.',table(['Timestamp','Action','Resource','Result'],state.data.audit.filter(matches).map(a=>[date(a.created_at),a.action,node('span',{class:'mono'},short(a.resource)),badge(a.result)]),'No audit events','Important system actions will be recorded here.')));}
  function render(){
    if(!state.user||!state.data.dashboard)return;
    const root=$('main-content');root.replaceChildren();
    if($('page-title'))$('page-title').textContent=state.view==='overview'?'Overview':state.view[0].toUpperCase()+state.view.slice(1);
    document.querySelectorAll('[data-view]').forEach(control=>{const active=control.dataset.view.replace(/^view-/,'')===state.view;control.classList.toggle('active',active);if(active)control.setAttribute('aria-current','page');else control.removeAttribute('aria-current');});
    ({overview:renderOverview,repositories:renderRepositories,scans:renderScans,findings:renderFindings,reports:renderReports,policies:renderPolicies,audit:renderAudit}[state.view]||renderOverview)(root);
    root.dataset.currentView=state.view;document.dispatchEvent(new CustomEvent('sentinelx:view-rendered',{detail:{key:'workspace:'+state.view}}));
  }
  async function restoreSession() {
    const form=$('auth-form'), submit=$('auth-submit'), toggle=$('auth-mode')||$('auth-toggle');
    const pending=node('p',{class:'session-loading',role:'status'},'Restoring your secure session…');
    form.before(pending);form.inert=true;submit.disabled=true;if(toggle)toggle.disabled=true;
    try {
      const response=await fetch(API+'/auth/me',{credentials:'same-origin',headers:{Accept:'application/json'}});
      if(response.status===401)return;
      if(!response.ok)throw new Error('Your session could not be checked. Sign in or refresh to retry.');
      state.user=await response.json();state.epoch++;$('user-email').textContent=state.user.email;
      await load();
      if(!state.user)return;
      $('auth-section').hidden=true;$('app-shell').hidden=false;status('Your workspace and saved scan results have been restored.');
    } catch(error) { clearSession(error.message||'Unable to restore your workspace. Please sign in again.'); }
    finally {pending.remove();form.inert=false;submit.disabled=false;if(toggle)toggle.disabled=false;}
  }
  function updateAuthMode(){const register=state.authMode==='register';if($('auth-title'))$('auth-title').textContent=register?'Create your workspace.':'Welcome back.';const subtitle=document.querySelector('.auth-subtitle');if(subtitle)subtitle.textContent=register?'Start connecting your code and security decisions.':'Sign in to your security control center.';if($('auth-mode-label'))$('auth-mode-label').textContent=register?'Already have an account?':'New to Sentinelx?';$('auth-submit').textContent=register?'Create account':'Sign in';const toggle=$('auth-mode')||$('auth-toggle');if(toggle)toggle.textContent=register?'Sign in':'Create an account';$('auth-password').autocomplete=register?'new-password':'current-password';$('auth-error').textContent='';}
  document.addEventListener('DOMContentLoaded',()=>{
    if(!$('app-status'))$('main-content').before(node('div',{id:'app-status',role:'status','aria-live':'polite',class:'app-status'}));
    $('auth-form').addEventListener('submit',event=>{event.preventDefault();const control=$('auth-submit');control.disabled=true;$('auth-error').textContent='';(async()=>{
      try{await post('/auth/'+state.authMode,{email:$('auth-email').value,password:$('auth-password').value});state.token=null;state.epoch++;$('auth-password').value='';state.user=await api('/auth/me');$('user-email').textContent=state.user.email;$('auth-section').hidden=true;$('app-shell').hidden=false;status('Loading your workspace…');await load();status('Workspace connected.');}
      catch(error){if(state.user)clearSession(error.message);else $('auth-error').textContent=error.message;}
      finally{control.disabled=false;}
    })();});
    ($('auth-mode')||$('auth-toggle'))?.addEventListener('click',()=>{state.authMode=state.authMode==='login'?'register':'login';updateAuthMode();});
    $('logout-button')?.addEventListener('click',()=>action(null,async()=>{try{await api('/auth/logout',{method:'POST'});}finally{clearSession('You have signed out.');}}));
    document.querySelectorAll('[data-view]').forEach(control=>control.addEventListener('click',()=>navigate(control.dataset.view.replace(/^view-/,''))));
    $('global-search')?.addEventListener('input',event=>{state.search=event.target.value.toLowerCase().trim();render();});
    $('refresh-button')?.addEventListener('click',event=>action(event.currentTarget,async()=>{await load();status('Workspace refreshed.');}));
    document.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key==='k'&&state.user){event.preventDefault();$('global-search')?.focus();}});
    updateAuthMode();
    restoreSession();
    setInterval(async()=>{
      if(!state.user||state.busy||!state.data.scans?.some(s=>['queued','running'].includes(s.status)))return;
      state.busy=true;const pendingIds=state.data.scans.filter(s=>['queued','running'].includes(s.status)).map(s=>s.id);try{await load(['overview','scans','reports'].includes(state.view)&&!$('detail-dialog'));if(state.user&&state.data.scans?.some(s=>pendingIds.includes(s.id)&&['completed','failed'].includes(s.status)))status('Scan finished. Open View report to review security gates, findings and remediation.');}catch(error){status(error.message,true);}finally{state.busy=false;}
    },2500);
  });
})();
