(function(factory){
  if(typeof module === 'object' && module.exports) module.exports = factory();
  else window.Workstations = factory();
})(function(){
  'use strict';
  const STATE = {queued:'В очереди',preflight:'Предварительная проверка',running:'Выполняется',verifying:'Проверка результата',
    successful:'Настройка завершена',degraded:'Завершено с замечаниями',failed:'Ошибка выполнения',
    unknown_requires_review:'UNKNOWN — требуется штатный разбор',waiting_reboot:'Ожидается перезагрузка',waiting_first_login:'Ожидается первый вход',cancelled:'Отменено'};
  const STAGE = {created:'Создано',queued:'Очередь',preflight:'Предварительная проверка',domain_join:'Присоединение к домену',
    domain_core_verify:'Проверка домена',configuration:'Настройка',apply:'Установка компонента',verify:'Проверка',
    download:'Загрузка',upgrade:'Обновление',identity:'Идентификация',network:'Сетевые проверки',complete:'Завершение',transaction:'Транзакция'};
  const FINDING = {network_only:'Нет подтверждённого соответствия AD',ad_only:'Объект есть только в AD',inventory_unconfirmed:'Связь с инвентаризацией не подтверждена',
    network_identity_ambiguous:'Неоднозначная сетевая идентичность',ad_computer_ambiguous:'Несколько объектов компьютера AD',employee_conflict:'Конфликт назначений сотрудника',
    employee_unusable:'Учётная запись сотрудника недоступна для настройки',employee_identity_changed:'Идентичность сотрудника изменилась',
    dns_forward_missing:'Нет прямой записи DNS',dns_forward_mismatch:'DNS и сетевой IP различаются',dns_reverse_missing:'Нет обратной записи DNS',
    dns_reverse_mismatch:'Обратная запись DNS указывает на другое имя',dns_reverse_zone_unavailable:'Обратная зона не подключена к сверке',
    dns_alias_loop:'Цикл псевдонимов DNS',dns_alias_ambiguous:'Неоднозначный псевдоним DNS',dns_record_malformed:'Некорректная запись DNS',inventory_deleted:'Карточка инвентаризации удалена'};
  function findingDetails(item){
    if(item.code!=='dns_record_malformed')return '';
    const evidence=item.evidence||{};
    return 'Зона: '+(typeof evidence.zone==='string'?evidence.zone:'нет сведений')+' · Имя: '+(typeof evidence.name==='string'?evidence.name:'нет сведений')+'. Запись исключена из сопоставления устройств.';
  }
  const EVENT = {task_start:'Задача начата',task_ok:'Задача выполнена',task_failed:'Ошибка задачи',task_unreachable:'ПК недоступен',task_skipped:'Задача пропущена',component_start:'Компонент начат',component_completed:'Компонент завершён'};
  const ACTION = {'plans.create':'Подготовка плана','component_plans.create':'План отдельного компонента','plans.apply':'Постановка в очередь','jobs.verify':'Проверка результата','jobs.cancel':'Отмена задания',
    'links.preview':'Сравнение привязки','links.confirm':'Подтверждение привязки','links.end':'Завершение привязки','link.confirmed':'Привязка подтверждена','link.ended':'Привязка завершена','source.collect':'Чтение источника','reconcile':'Сверка источников','job.stage':'Этап задания'};
  function verificationLabel(value){return ({technical_verified:'Технически проверено',compliant:'Технически проверено',functional_verification_required:'Нужна проверка пользователем',
    missing:'Компонент отсутствует',drifted:'Обнаружены отличия',blocked:'Проверка заблокирована',unknown:'Исход проверки неизвестен',not_selected:'Не выбран',
    installed_verified:'Установка проверена',unverified:'Не проверено',successful:'Проверено',failed:'Проверка не пройдена',not_required:'Не требуется'})[value] || 'Сведений о проверке нет';}
  function jobMessage(job){
    const text = STATE[job.state] || 'Состояние не опубликовано';
    if(job.state === 'waiting_reboot') return text + '. Согласуйте и выполните перезагрузку отдельно.';
    if(job.state === 'waiting_first_login') return text + '. Нужен вход выбранного сотрудника на ПК.';
    if(job.state === 'unknown_requires_review') return text + '. Повторный запуск запрещён до штатной проверки.';
    if(job.state === 'failed') return text + '. Изучите этап ошибки и журнал.';
    if(job.state === 'queued') return text + (job.queue_position ? ' · место ' + job.queue_position : '') + '. Ожидаются проверки контроллера.';
    return text;
  }
  function canApply(plan,{confirmed=false,allowed=false,submitted=false}={},now=Date.now()){
    return !!(allowed && confirmed && !submitted && plan && /^[0-9a-f]{64}$/.test(plan.sha256)
      && plan.action !== 'blocked' && (!plan.preflight || plan.preflight.ready !== false)
      && (!String(plan.plan_id).startsWith('setup-component-') || ['noop','install','repair'].includes(plan.action))
      && [ 'setup-' + plan.sha256, 'setup-component-' + plan.sha256 ].includes(plan.plan_id)
      && Number.isFinite(Date.parse(plan.expires_at)) && Date.parse(plan.expires_at) > now);
  }
  async function readReadyMachines(readPage){
    const machines=new Map();let offset=0,total=null,revision=null;
    const invalid=()=>new Error('Список ПК неполон или источник изменился. Обновите список.');
    for(let page=0;page<100;page++){
      const data=await readPage(offset),current=data?.source_revision??data?.generation;
      if(!Array.isArray(data?.devices)||data.devices.length>100||!Number.isInteger(data.total)||data.total<0||data.total>10000
        ||!Number.isInteger(data.next_offset)||data.next_offset!==offset+data.devices.length||data.next_offset>data.total
        ||typeof current!=='string'||!current||(total!==null&&(data.total!==total||current!==revision)))throw invalid();
      total=data.total;revision=current;
      for(const row of data.devices){
        if(!row||typeof row.machine_uuid!=='string'||!row.machine_uuid||row.registration_state!=='ready')continue;
        if(machines.has(row.machine_uuid))throw invalid();
        machines.set(row.machine_uuid,row);
      }
      if(data.next_offset===total)return Array.from(machines.values());
      if(!data.devices.length)throw invalid();
      offset=data.next_offset;
    }
    throw invalid();
  }
  class EventCursor {
    constructor({after=0}={}){this.after=Number.isInteger(after)&&after>=0?after:0;}
    consume(page){
      const events=[]; let current=this.after;
      if(!page || !Array.isArray(page.events) || page.events.length>1000 || !Number.isInteger(page.total) || page.total<current || page.total>10000) return {events,gap:true};
      for(const event of page.events){
        if(!Number.isInteger(event.sequence) || event.sequence<1) return {events:[],gap:true};
        if(event.sequence<=current) continue;
        if(event.sequence!==current+1) return {events:[],gap:true};
        events.push(event); current=event.sequence;
      }
      if(page.next_sequence!==current || current>page.total || current<page.total&&events.length===0) return {events:[],gap:true};
      this.after=current; return {events,gap:false};
    }
  }
  class Poller {
    constructor(read,{visible=()=>!document.hidden,schedule=(fn,delay)=>setTimeout(fn,delay),cancel=id=>clearTimeout(id),onError=()=>{}}={}){
      Object.assign(this,{read,visible,schedule,cancel,onError});this.stopped=true;this.running=false;this.failures=0;this.timer=null;
    }
    start(){this.stopped=false;return this.tick();}
    async tick(){
      if(this.stopped||this.running) return;
      this.running=true;
      try {if(this.visible()){if(await this.read()===false){this.stop();return;}this.failures=0;}}
      catch(error){this.failures=Math.min(4,this.failures+1);this.onError(error);}
      finally {this.running=false;if(!this.stopped)this.timer=this.schedule(()=>this.tick(),Math.min(30000,2000*2**this.failures));}
    }
    wake(){if(this.stopped||!this.visible()||this.running)return;this.cancel(this.timer);return this.tick();}
    stop(){this.stopped=true;this.cancel(this.timer);}
  }
  function nonce(){
    if(globalThis.crypto.randomUUID) return globalThis.crypto.randomUUID();
    const bytes=globalThis.crypto.getRandomValues(new Uint8Array(16));bytes[6]=(bytes[6]&15)|64;bytes[8]=(bytes[8]&63)|128;
    const hex=Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
    return [hex.slice(0,8),hex.slice(8,12),hex.slice(12,16),hex.slice(16,20),hex.slice(20)].join('-');
  }
  function mount(root){
    const one=selector=>root.querySelector(selector), all=selector=>Array.from(root.querySelectorAll(selector));
    const permissions=JSON.parse(root.dataset.capabilities||'{}'), pollers=[], users=new Map(), pending=new Map();
    let deviceRows=[], sourceRevision=null, linkPreview=null, currentJob=null;
    function el(tag,text,className){const value=document.createElement(tag);if(text!==undefined&&text!==null)value.textContent=String(text);if(className)value.className=className;return value;}
    function anchor(text,url){const value=el('a',text);value.href=url;return value;}
    function notice(selector,text){const target=one(selector);if(target){target.textContent=text||'';target.hidden=!text;}}
    function error(value){notice('[data-error]',(value.message||'Операция не завершена')+(value.code?'\nКод: '+value.code:'')+(value.next_action?'\n'+value.next_action:''));}
    function on(target,event,handler){if(target)target.addEventListener(event,async evt=>{evt.preventDefault();try{await handler(evt);}catch(exc){error(exc);}});}
    async function request(path,{method='GET',body}={}){
      const abort=new AbortController(),timeout=setTimeout(()=>abort.abort(),45000);
      try {
        const result=await fetch('/api/v1/workstations'+path,{method,credentials:'same-origin',cache:'no-store',signal:abort.signal,
          headers:{'Content-Type':'application/json','X-CSRF-Token':root.dataset.csrf},body:body===undefined?undefined:JSON.stringify(body)});
        const value=await result.json();
        if(!result.ok||value.status!=='ok'){const detail=value.error||{};throw Object.assign(new Error('Запрос не завершён'),detail,{status:result.status});}
        return value.data;
      } catch(exc){if(exc.name==='AbortError'||exc instanceof TypeError)throw Object.assign(new Error('Ответ панели не получен. Сохраните идентификатор исходного запроса и проверьте состояние операции.'),{code:'workstations_browser_transport_unavailable'});throw exc;}
      finally {clearTimeout(timeout);}
    }
    function table(target,headers,rows){
      if(!target)return;target.replaceChildren();
      if(!rows.length){target.append(el('p','Нет опубликованных данных.','muted'));return;}
      const wrapper=el('div',null,'ws-table'),grid=el('table'),head=el('tr'),body=el('tbody');
      headers.forEach(text=>head.append(el('th',text)));const thead=el('thead');thead.append(head);grid.append(thead);
      rows.forEach(values=>{const row=el('tr');values.forEach(value=>{const cell=el('td');cell.append(value instanceof Node?value:document.createTextNode(String(value??'—')));row.append(cell);});body.append(row);});
      grid.append(body);wrapper.append(grid);target.append(wrapper);
    }
    function poll(read){const value=new Poller(read,{onError:error});pollers.push(value);value.start();return value;}
    async function action(path,parameters){
      notice('[data-error]','');const key=path+JSON.stringify(parameters);if(!pending.has(key))pending.set(key,nonce());
      const requestId=pending.get(key);notice('[data-operation]','Регистрируем запрос '+requestId+'…');
      const result=await request(path,{method:'POST',body:{...parameters,request_id:requestId}});
      if(!result.operation_id)throw Object.assign(new Error('Идентификатор операции ещё не опубликован. Повторите чтение исходного запроса.'),{code:'workstations_operation_missing'});
      return new Promise((resolve,reject)=>{poll(async()=>{
        let current;try{current=await request('/operations/'+encodeURIComponent(result.operation_id));}
        catch(exc){if([401,403,404].includes(exc.status)){reject(exc);return false;}throw exc;}
        const phase=(current.phases||[]).at(-1);notice('[data-operation]','Операция '+result.operation_id+' · '+(phase?({controller:'Проверка контроллером',comparison:'Сравнение источников',registered:'Регистрация'}[phase.stage]||phase.stage):current.status));
        if(['registered','running'].includes(current.status))return;
        if(current.status==='succeeded'){notice('[data-operation]','Операция завершена · '+result.operation_id);pending.delete(key);resolve(current.data);}
        else {const detail=current.error||{};reject(Object.assign(new Error(current.status==='unknown'?'UNKNOWN: исход операции не подтверждён. Новый запуск не выполняйте.':'Операция завершилась с ошибкой.'),detail));}
        return false;
      });});
    }
    async function summary(){
      const data=await request('/status');
      notice('[data-summary]',!data.enabled?'Интеграция ещё не настроена':data.queue_status==='unavailable'?'Контроллер недоступен · '+(data.error_code||'нет сведений'):
        'Выполняется: '+(data.executing_count||0)+' · в очереди: '+(data.queued_count||0)+(data.historical_unknown_count?' · UNKNOWN в истории: '+data.historical_unknown_count:''));
    }
    function options(select,rows,label){if(!select)return;select.replaceChildren(new Option('Выберите значение',''));rows.forEach(row=>select.append(new Option(label(row),row.id)));}
    function chooseStep(name){all('[data-step]').forEach(item=>{if(item.dataset.step===name)item.setAttribute('aria-current','step');else item.removeAttribute('aria-current');});}
    function employee(){const radio=one('[name=employee_guid]:checked');if(!radio||!users.has(radio.value))throw new Error('Выберите конкретного сотрудника в результатах поиска.');return users.get(radio.value);}
    on(one('[data-employee-search]'),'submit',async evt=>{
      const form=new FormData(evt.currentTarget);notice('[data-search-status]','Ищем сотрудников…');
      const result=await request('/directory/search',{method:'POST',body:{query:String(form.get('query')).trim(),limit:50}});
      const target=one('[data-search-results]');target.replaceChildren();users.clear();
      result.users.forEach(user=>{users.set(user.object_guid,user);const label=el('label',null,'ws-person'),radio=el('input');radio.type='radio';radio.name='employee_guid';radio.value=user.object_guid;radio.disabled=user.state!=='enabled';
        const copy=el('span',user.display_name||user.login);copy.append(el('small',[user.login,user.upn,user.department,({enabled:'Доступен',disabled:'Отключён',locked:'Заблокирован',expired:'Истёк срок',password_expired:'Требуется смена пароля'})[user.state]||'Состояние неизвестно'].filter(Boolean).join(' · ')));label.append(radio,copy);target.append(label);});
      notice('[data-search-status]',result.truncated?'Найдено больше 50 записей. Уточните ФИО или логин.':result.users.length?'Выберите нужную запись.':'Сотрудник не найден.');chooseStep('employee');
    });
    let deviceOffset=0,moreDevices=false;
    async function devices(reset=true){
      if(reset){deviceRows=[];deviceOffset=0;}
      const data=await request('/devices?offset='+deviceOffset+'&limit=100');deviceRows.push(...data.devices);sourceRevision=data.source_revision;
      deviceOffset=data.next_offset;moreDevices=Number.isInteger(deviceOffset)&&deviceOffset<data.total;
      const filter=root.dataset.inventoryFilter,network=root.dataset.networkFilter;
      const rows=deviceRows.filter(row=>(!filter||row.inventory_asset_id===filter)&&(!network||(row.network_keys||[]).includes(network)||row.device_key===network));
      table(one('[data-device-list]'),['Компьютер','Сеть','Сотрудник','Инвентаризация','Сопоставление AD'],rows.map(row=>[
        anchor(row.hostname||row.device_key,'/workstations/devices/'+encodeURIComponent(row.device_key)),(row.ips||[row.ip]).filter(Boolean).join(', '),
        row.assigned_user?.display_name||row.domain_assignment?.login||'Не подтверждён',row.inventory_name||'Связь не подтверждена',({confirmed:'Подтверждено',candidate:'Нужно сравнение',ambiguous:'Конфликт',only_directory:'Только AD'})[row.ad_computer_state]||'Нет сведений']));
      if(data.stale)one('[data-device-list]')?.prepend(el('p','Показана последняя полная сверка. Источники устарели либо связи или инвентаризация изменились после неё. Запросите свежую сверку.','alert warn'));
      if(one('[data-more-devices]'))one('[data-more-devices]').hidden=!moreDevices;
      if((filter||network)&&!rows.length&&moreDevices)await devices(false);
    }
    let machineRead=null;
    function selectableMachines(){
      const select=one('[name=machine_uuid]');if(!select)return Promise.resolve();if(machineRead)return machineRead;
      const previous=select.value;select.disabled=true;options(select,[],()=>{});
      machineRead=readReadyMachines(offset=>request('/devices?offset='+offset+'&limit=100')).then(rows=>{
        options(select,rows.map(row=>({...row,id:row.machine_uuid})),row=>row.hostname||row.id);
        if(rows.some(row=>row.machine_uuid===previous))select.value=previous;
      }).finally(()=>{select.disabled=false;machineRead=null;});
      return machineRead;
    }
    on(one('[data-refresh-devices]'),'click',()=>Promise.all([devices(),selectableMachines()]));on(one('[data-more-devices]'),'click',()=>devices(false));
    async function catalog(){const value=await request('/catalog');options(one('[name=ou_id]'),value.ous,row=>row.name);options(one('[name=software_profile]'),value.profiles,row=>row.name||row.id);options(one('[name=component_id]'),value.components,row=>row.name||row.id);}
    on(one('[name=kind]'),'change',()=>{const component=one('[name=kind]').value==='component';all('[data-full-option]').forEach(node=>node.hidden=component);all('[data-component-option]').forEach(node=>node.hidden=!component);});
    function setupRequirements(){const component=one('[name=kind]')?.value==='component';
      ['ou_id','software_profile'].forEach(name=>{const select=one('[name='+name+']');if(select){select.required=!component;select.disabled=component;}});
      const select=one('[name=component_id]');if(select){select.required=component;select.disabled=!component;}}
    on(one('[name=kind]'),'change',setupRequirements);setupRequirements();
    on(one('[name=machine_uuid]'),'change',()=>chooseStep('employee'));
    ['ou_id','software_profile','remote_access_profile','component_id'].forEach(name=>on(one('[name='+name+']'),'change',()=>chooseStep('options')));
    on(one('[data-setup-form]'),'submit',async evt=>{
      const form=new FormData(evt.currentTarget),component=form.get('kind')==='component',button=root.querySelector('button[form=ws-setup-form]');
      const selected=component?null:employee();let payload={machine_uuid:form.get('machine_uuid')};
      if(!payload.machine_uuid)throw new Error('Выберите зарегистрированный готовый компьютер.');
      payload=component?{...payload,component_id:form.get('component_id')}:{...payload,user_login:selected.login,user_guid:selected.object_guid,user_sid:selected.object_sid,
        ou_id:form.get('ou_id'),software_profile:form.get('software_profile'),remote_access_profile:form.get('remote_access_profile')};
      button.disabled=true;button.textContent='Проверяем состояние ПК…';chooseStep('plan');one('[data-plan-result]').replaceChildren(el('p','Готовим защищённый план. Установка ещё не выполняется.'));
      try{const result=await action(component?'/component-plans':'/plans',payload);const target=one('[data-plan-result]');target.replaceChildren(anchor('Открыть готовый план и проверить изменения','/workstations/plans/'+encodeURIComponent(result.plan_id)));chooseStep('confirm');}finally{button.disabled=false;button.textContent='Подготовить план';}
    });
    const planNode=one('[data-plan]');if(planNode){
      const plan=JSON.parse(planNode.textContent),form=one('[data-apply-plan]'),button=form.querySelector('button');let submitted=root.dataset.submitted==='true';
      const update=()=>{button.disabled=!canApply(plan,{confirmed:form.elements.confirmed.checked,allowed:permissions.apply,submitted});notice('[data-plan-expiry]',Date.parse(plan.expires_at)<=Date.now()?'Срок плана истёк. Подготовьте новый план.':'');};
      on(form,'change',update);update();poll(()=>{update();return !submitted&&Date.parse(plan.expires_at)>Date.now();});
      on(form,'submit',async()=>{if(!canApply(plan,{confirmed:form.elements.confirmed.checked,allowed:permissions.apply,submitted}))throw new Error('Подтвердите актуальный показанный план.');submitted=true;update();
        const result=await action('/plans/'+encodeURIComponent(plan.plan_id)+'/apply',{sha256:plan.sha256,kind:plan.plan_id.startsWith('setup-component-')?'component':'full_setup'});
        window.location.assign('/workstations/jobs/'+encodeURIComponent(result.job_id));});
    }
    if(root.dataset.existingOperation&&permissions.apply)poll(async()=>{const value=await request('/operations/'+encodeURIComponent(root.dataset.existingOperation));
      if(['registered','running'].includes(value.status)){notice('[data-operation]','Ожидаем исходную операцию '+value.operation_id);return;}
      if(value.data?.job_id){const target=one('[data-existing-apply]');target.replaceChildren(el('p','Исходный запрос принят.'),anchor('Открыть исходное задание','/workstations/jobs/'+encodeURIComponent(value.data.job_id)));}
      else if(value.status==='unknown')error(Object.assign(new Error('UNKNOWN: исход исходного запроса не подтверждён. Повторная отправка недоступна.'),value.error||{}));
      return false;});
    let jobOffset=0;
    async function jobs(reset=true){if(reset){jobOffset=0;one('[data-jobs]').replaceChildren();}const data=await request('/jobs?offset='+jobOffset+'&limit=100');
      data.jobs.forEach(job=>{const row=el('article',null,'ws-card');row.append(anchor(job.job_id,'/workstations/jobs/'+encodeURIComponent(job.job_id)),el('p',jobMessage(job)));one('[data-jobs]').append(row);});
      jobOffset=data.next_offset;one('[data-more-jobs]').hidden=jobOffset>=data.total;}
    on(one('[data-refresh-jobs]'),'click',()=>jobs());on(one('[data-more-jobs]'),'click',()=>jobs(false));
    function appendEvent(target,event){const row=el('li'),time=el('time',new Date(event.timestamp).toLocaleString('ru-RU'));time.dateTime=event.timestamp;
      row.append(time,el('span',[event.sequence?'№ '+event.sequence:null,event.component_id,STAGE[event.stage]||event.stage,EVENT[event.type]||ACTION[event.action]||event.action,
        STATE[event.status]||({succeeded:'Завершено',success:'Получено',unknown:'UNKNOWN',error:'Ошибка',running:'Выполняется'})[event.status]||event.status,
        event.changed===true?'Изменено':event.changed===false?'Без изменений':null].filter(Boolean).join(' · ')));
      if(event.task_id||event.code||event.actor)row.append(el('small',[event.task_id,event.code,event.actor].filter(Boolean).join(' · '),'mono'));
      target.append(row);}
    if(root.dataset.jobId){
      const jobId=root.dataset.jobId,storageKey='workstations.events.'+jobId;let cursor=new EventCursor();
      try{cursor=new EventCursor({after:Number(sessionStorage.getItem(storageKey))||0});}catch(_){}
      if(cursor.after)notice('[data-event-evidence]','Продолжаем с события '+cursor.after+'. Предыдущую историю можно загрузить сначала или открыть в полном журнале.');
      const refresh=async()=>{
        const data=await request('/jobs/'+encodeURIComponent(jobId));currentJob=data.job;
        notice('[data-job-state]',currentJob.state==='queued'?jobMessage(currentJob):STATE[currentJob.state]||'Состояние не опубликовано');
        const guidance={waiting_first_login:'Войдите на ПК под выбранным сотрудником. Затем запросите проверку результата.',
          waiting_reboot:'Согласуйте и выполните перезагрузку отдельно. Затем запросите проверку результата.',
          unknown_requires_review:'Исход не подтверждён. Повторный запуск запрещён до штатного review.',
          failed:'Изучите этап ошибки и безопасный журнал перед подготовкой нового плана.'};
        notice('[data-job-action]',currentJob.operator_action_required?(guidance[currentJob.state]||jobMessage(currentJob))+(currentJob.error_code?' · '+currentJob.error_code:''):'');
        await summary();
        const history=one('[data-stage-history]');history.replaceChildren();(currentJob.history||[]).forEach((stage,index,rows)=>{const next=rows[index+1],duration=next?Math.max(0,Math.round((Date.parse(next.at)-Date.parse(stage.at))/1000)):null;
          history.append(el('li',(STAGE[stage.stage]||stage.stage)+' · '+(STATE[stage.state]||stage.state)+' · '+new Date(stage.at).toLocaleString('ru-RU')+(duration!==null?' · '+duration+' с':'')));});
        table(one('[data-job-components]'),['Компонент','Изменения','Установка','Техническая проверка','Проверка пользователем'],Object.entries(currentJob.components||{}).map(([id,value])=>[
          id,value.changed===true?'Изменено':value.changed===false?'Без изменений':'Нет сведений',verificationLabel(value.verification?.installation_status),
          verificationLabel(value.verification?.status||value.verification?.acceptance_status),value.verification?.acceptance_status==='technical_verified'?'Отдельная проверка пользователем не требуется':verificationLabel(value.verification?.acceptance_status)]));
        if(one('[data-cancel-job]'))one('[data-cancel-job]').disabled=currentJob.state!=='queued';
        let page;do{page=await request('/jobs/'+encodeURIComponent(jobId)+'/events?after='+cursor.after+'&limit=1000');const result=cursor.consume(page);
          if(result.gap){notice('[data-event-evidence]','Обнаружен пропуск или несогласованная история. Сведения нельзя считать полными; загрузите события сначала.');return;}
          result.events.forEach(event=>appendEvent(one('[data-job-events]'),event));try{sessionStorage.setItem(storageKey,String(cursor.after));}catch(_){}
          if(!page.total)notice('[data-event-evidence]','Опубликованных событий задач нет. История этапов показана выше.');
          else if(result.events.length)notice('[data-event-evidence]','Получено событий: '+cursor.after+' из '+page.total);
        }while(cursor.after<page.total);
      };
      poll(refresh);
      on(one('[data-restart-events]'),'click',async()=>{cursor=new EventCursor();one('[data-job-events]').replaceChildren();await refresh();});
      on(one('[data-verify-job]'),'click',async()=>{await action('/jobs/'+encodeURIComponent(jobId)+'/verify',{});await refresh();});
      on(one('[data-cancel-job]'),'click',async()=>{if(!currentJob||currentJob.state!=='queued')return;await action('/jobs/'+encodeURIComponent(jobId)+'/cancel',{sha256:currentJob.plan_sha256});await refresh();});
    }
    let currentDevice=null;
    async function detail(){const data=await request('/devices/'+encodeURIComponent(root.dataset.deviceKey));currentDevice=data.device;sourceRevision=data.source_revision;const row=data.device;
      const explicit=data.links.find(link=>link.status==='confirmed');const assigned=row.native_assignment||row.domain_assignment?row.assigned_user||row.native_assignment||row.domain_assignment:explicit?.user;
      table(one('[data-device-detail]'),['Сведения','Значение'],[['Компьютер',row.hostname||row.device_key],['Сеть',(row.ips||[row.ip]).filter(Boolean).join(', ')],
        ['Сотрудник',assigned?.display_name||assigned?.login||'Не подтверждён'],['Идентичность',row.identity_state==='ambiguous'?'Конфликт — подтверждение недоступно':'Наблюдение; сверьте устойчивые идентификаторы'],
        ['Инвентаризация',row.inventory_asset_id?anchor(row.inventory_name||'Открыть карточку','/inventory/assets/'+encodeURIComponent(row.inventory_asset_id)):'Нет подтверждённой карточки']]);
      if(data.stale)one('[data-device-detail]').prepend(el('p','Сведения сверки устарели или связи изменились. Подтверждённые привязки ниже прочитаны непосредственно из панели.','alert warn'));
      if(row.network_keys?.length){const p=el('p');p.append(anchor('Сравнить с инвентаризацией','/inventory/network-links?network_key='+encodeURIComponent(row.network_keys[0])+(row.inventory_asset_id?'&asset_id='+encodeURIComponent(row.inventory_asset_id):'')));one('[data-device-detail]').append(p);}
      options(one('[name=computer_guid]'),(row.ad_computer_candidates||[]).map(value=>({id:value.object_guid,...value})),value=>value.dns_hostname||value.login);
      const target=one('[data-device-links]');target.replaceChildren();data.links.forEach(value=>{const card=el('article',null,'ws-card');card.append(el('h3',value.user?.display_name||value.user?.login||'Сотрудник'),el('p',value.status==='confirmed'?'Привязка подтверждена':value.status==='ended'?'Привязка завершена':'Превью привязки'));
        if(value.status==='confirmed'&&permissions.link){const form=el('form',null,'ws-grid'),input=el('input'),button=el('button','Завершить привязку','button secondary');input.name='reason';input.placeholder='Причина завершения';input.required=true;input.maxLength=2000;input.setAttribute('aria-label','Причина завершения привязки');button.type='submit';form.append(input,button);on(form,'submit',async()=>{await action('/links/'+value.id+'/end',{expected_revision:value.revision,reason:input.value});await detail();});card.append(form);}target.append(card);});
    }
    on(one('[data-link-preview]'),'submit',async evt=>{if(currentDevice?.identity_state==='ambiguous')throw new Error('Сначала устраните неоднозначность устройства.');const user=employee(),form=new FormData(evt.currentTarget);
      linkPreview=await action('/links/preview',{device_key:root.dataset.deviceKey,user_guid:user.object_guid,computer_guid:form.get('computer_guid')||null,source_revision:sourceRevision});
      one('[data-link-result]').replaceChildren(el('p','Будет подтверждена связь: '+(linkPreview.user.display_name||linkPreview.user.login)+' · '+linkPreview.user.login+'; действует до '+new Date(linkPreview.expires_at).toLocaleTimeString('ru-RU')));one('[data-link-confirm]').hidden=false;});
    on(one('[data-link-confirm]'),'submit',async evt=>{if(!linkPreview)throw new Error('Подготовьте свежую привязку.');await action('/links/confirm',{preview_id:linkPreview.id,expected_revision:linkPreview.revision,reason:new FormData(evt.currentTarget).get('reason')});one('[data-link-confirm]').hidden=true;linkPreview=null;await detail();});
    async function sources(){const data=await request('/sources');table(one('[data-sources]'),['Источник','Последняя попытка','Последнее полное наблюдение','Объекты','Состояние'],data.sources.map(row=>[
      ({controller:'Контроллер',ad:'Каталог AD',dns:'DNS',netctl:'Устройства сети'})[row.source]||row.source,row.last_attempt?new Date(row.last_attempt).toLocaleString('ru-RU'):'Нет попыток',
      row.observed_at?new Date(row.observed_at).toLocaleString('ru-RU'):'Нет полного снимка',row.object_count,(row.stale?'Устарело · ':'')+row.status+(row.error_code?' · '+row.error_code:'')]));}
    on(one('[data-refresh-sources]'),'click',sources);
    let findingOffset=0;
    async function findings(reset=true){if(reset){findingOffset=0;one('[data-findings]').replaceChildren();}const data=await request('/findings?offset='+findingOffset+'&limit=100');data.findings.forEach(item=>{
      const card=el('article',null,'ws-card');card.append(el('h3',FINDING[item.code]||item.code),el('p',item.status==='acknowledged'?'Замечание просмотрено; причина конфликта сохраняется':'Требуется сравнение'),
        anchor(item.device_key.startsWith('source:')?'Открыть источники':'Открыть устройство',item.device_key.startsWith('source:')?'/workstations/sources':'/workstations/devices/'+encodeURIComponent(item.device_key)));
      const details=findingDetails(item);if(details)card.append(el('p',details));
      if(permissions.diagnose){const form=el('form',null,'ws-grid'),input=el('input'),button=el('button','Отметить просмотренным','button secondary');input.required=true;input.maxLength=2000;input.placeholder='Основание отметки';input.setAttribute('aria-label','Основание отметки замечания');button.type='submit';form.append(input,button);on(form,'submit',async()=>{await action('/findings/'+item.id+'/acknowledge',{expected_revision:item.revision,reason:input.value});await findings();});card.append(form);}one('[data-findings]').append(card);});
      findingOffset=data.next_offset;one('[data-more-findings]').hidden=findingOffset===null;if(!data.findings.length&&reset)one('[data-findings]').append(el('p','Замечаний в последней полной сверке нет. Проверьте свежесть источников.'));}
    on(one('[data-more-findings]'),'click',()=>findings(false));on(one('[data-reconcile]'),'click',async()=>{await action('/reconcile',{});await findings();});
    let journalCursor=null,journalFilters={};
    async function journal(reset=true){if(reset){journalCursor=null;one('[data-journal]').replaceChildren();}const params=new URLSearchParams(journalFilters);params.set('limit','100');if(journalCursor)params.set('cursor',journalCursor);
      const data=await request('/journal?'+params);data.events.forEach(event=>appendEvent(one('[data-journal]'),event));journalCursor=data.next_cursor;one('[data-more-journal]').hidden=!journalCursor;one('[data-journal-export]').href='/api/v1/workstations/journal/export?'+params;
      notice('[data-journal-evidence]',data.native_complete ? 'Опубликованная история контроллера прочитана полностью. Выборка отображается по страницам.' : 'История контроллера недоступна или неполна. Показанные события нельзя считать полной историей.' + (data.native_errors||[]).map(error=>' '+error.code).join(''));}
    on(one('[data-journal-filter]'),'submit',async evt=>{journalFilters=Object.fromEntries(Array.from(new FormData(evt.currentTarget)).filter(([,value])=>value));await journal();});on(one('[data-more-journal]'),'click',()=>journal(false));
    if(!root.dataset.jobId)summary().catch(error);
    if(permissions.read){if(one('[data-device-list]'))devices().catch(error);if(one('[data-setup-form]')){catalog().catch(error);selectableMachines().catch(error);}if(one('[data-jobs]'))jobs().catch(error);if(root.dataset.deviceKey)detail().catch(error);if(one('[data-sources]'))sources().catch(error);if(one('[data-findings]'))findings().catch(error);}
    document.addEventListener('visibilitychange',()=>pollers.forEach(value=>value.wake()));window.addEventListener('pagehide',()=>pollers.forEach(value=>value.stop()),{once:true});
  }
  if(typeof document!=='undefined'){const boot=()=>document.querySelectorAll('[data-workstations]').forEach(mount);if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',boot);else boot();}
  return {EventCursor,Poller,jobMessage,verificationLabel,canApply,findingDetails,readReadyMachines,mount};
});
