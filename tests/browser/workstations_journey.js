// Loopback-only browser acceptance. A Playwright MCP adapter may call the
// exported function; the CLI runner uses an already installed Playwright module.
module.exports = async (page, output) => {
  const base='http://127.0.0.1:18881';
  const check=(condition,message)=>{if(!condition)throw new Error(message);};
  const counts=async()=>page.request.get(base+'/__fixture/state').then(response=>response.json());
  const consoleErrors=[],apiFailures=[],eventOffsets=[];
  const listener=message=>{if(message.type()==='error')consoleErrors.push(message.text());};
  const responses=response=>{if(response.url().includes('/api/v1/workstations')&&response.status()>=400)apiFailures.push(response.status());
    if(response.url().includes('/events?'))eventOffsets.push(new URL(response.url()).searchParams.get('after'));};
  page.on('console',listener);page.on('response',responses);
  try {
    await page.setViewportSize({width:1360,height:900});
    await page.goto(base+'/workstations');
    if(page.url().endsWith('/login')){
      await page.getByRole('textbox',{name:'Логин',exact:true}).fill('synthetic');
      await page.getByRole('textbox',{name:'Пароль',exact:true}).fill('synthetic-browser-only');
      await page.getByRole('button',{name:'Войти',exact:true}).click();
      await page.goto(base+'/workstations');
    }
    check(page.url()===base+'/workstations','Wrong fixture page');
    await page.evaluate(()=>sessionStorage.clear());
    await page.locator('[name=machine_uuid] option[value="00000000-0000-0000-0000-0000000003e9"]').waitFor({state:'attached'});
    await page.locator('[data-device-list] tbody tr').nth(99).waitFor();
    check(await page.locator('[data-device-list] tbody tr').count()===100,'Device table pagination changed');
    check(await page.getByRole('link',{name:'Тестовый ПК',exact:true}).count()===0,'Fixture target must lie beyond the first device page');
    await page.getByLabel('Зарегистрированный компьютер').selectOption({label:'Тестовый ПК'});
    while(await page.getByRole('link',{name:'Тестовый ПК',exact:true}).count()===0){
      const count=await page.locator('[data-device-list] tbody tr').count();
      await page.locator('[data-more-devices]').click();
      await page.waitForFunction(n=>document.querySelectorAll('[data-device-list] tbody tr').length>n,count);
      check(await page.getByLabel('Зарегистрированный компьютер').inputValue()==='00000000-0000-0000-0000-0000000003e9','Loading table pages cleared the selected PC');
    }
    await page.getByLabel('Подразделение компьютеров (OU)').selectOption({label:'Тестовые компьютеры'});
    await page.getByLabel('Комплект программ').selectOption({label:'Офисный комплект без электронной подписи'});
    await page.getByRole('searchbox').fill('Тестовый');
    await page.getByRole('button',{name:'Найти сотрудника',exact:true}).click();
    await page.getByRole('radio').nth(1).waitFor();
    check(await page.locator('[name=employee_guid]:checked').count()===0,'Employee must be explicitly selected');
    check(await page.locator('[data-search-results] img').count()===0,'Directory text became markup');
    check(await page.getByRole('button',{name:'Создать пользователя',exact:true}).isDisabled(),'Employee creation must be disabled');
    await page.getByRole('radio').first().check();
    await page.getByRole('button',{name:'Подготовить план',exact:true}).click();
    await page.getByRole('link',{name:'Открыть готовый план и проверить изменения'}).click();
    const planUrl=page.url(),before=await counts();
    check(await page.getByRole('button',{name:'Поставить в очередь',exact:true}).isDisabled(),'Unconfirmed plan was enabled');
    await page.getByRole('checkbox',{name:'Подтверждаю показанный план'}).check();
    await page.getByRole('button',{name:'Поставить в очередь',exact:true}).click();
    await page.waitForURL('**/workstations/jobs/**');
    await page.waitForFunction(()=>document.querySelectorAll('[data-job-events] li').length===205);
    const jobUrl=page.url();
    check((await counts()).apply_count===before.apply_count+1,'Apply submitted more than once');
    check((await counts()).verify_count===before.verify_count,'GET polling invoked verification');
    check(eventOffsets.includes('0')&&eventOffsets.includes('100')&&eventOffsets.includes('200'),'Event pagination did not drain');
    check((await page.locator('[data-job-state]').textContent()).includes('место 1'),'Queue position missing');
    check((await page.locator('[data-job-components]').textContent()).includes('Технически проверено'),'Technical verification missing');
    check((await page.locator('[data-job-components]').textContent()).includes('Нужна проверка пользователем'),'Functional gate was hidden');
    await page.goto(planUrl);
    check(await page.getByRole('button',{name:'Поставить в очередь',exact:true}).isDisabled(),'Reload enabled a consumed plan');
    await page.getByRole('link',{name:'Открыть исходное задание',exact:true}).first().click();
    await page.locator('[data-event-evidence]').filter({hasText:'Продолжаем с события 205'}).waitFor();
    check(await page.locator('[data-job-events] li').count()===0,'Reload invented old event content');
    await page.getByRole('button',{name:'Загрузить события сначала',exact:true}).click();
    await page.waitForFunction(()=>document.querySelectorAll('[data-job-events] li').length===205);
    await page.request.post(base+'/__fixture/job/waiting_first_login');
    await page.waitForFunction(()=>document.querySelector('[data-job-state]').textContent.includes('Ожидается первый вход'));
    await page.screenshot({path:output+'/workstations-desktop-job.png',fullPage:false});
    await page.setViewportSize({width:390,height:844});
    await page.waitForFunction(()=>document.querySelector('.sidebar').getBoundingClientRect().right<=0);
    check(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile page overflows');
    await page.screenshot({path:output+'/workstations-mobile-job.png',fullPage:false});
    for(const [state,text] of [['waiting_reboot','перезагрузка'],['unknown_requires_review','UNKNOWN'],['failed','Ошибка']]){
      await page.request.post(base+'/__fixture/job/'+state);
      await page.waitForFunction(value=>document.querySelector('[data-job-state]').textContent.toLowerCase().includes(value.toLowerCase()),text);
    }
    check((await counts()).verify_count===before.verify_count,'State polling ran verification');
    await page.getByRole('button',{name:'Проверить результат',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('[data-job-state]').textContent.includes('Настройка завершена'));
    check((await counts()).verify_count===before.verify_count+1,'Explicit verification was not executed once');
    check((await counts()).apply_count===before.apply_count+1,'Watching or reopening replayed apply');
    await page.setViewportSize({width:1360,height:900});
    await page.goto(base+'/workstations');
    while(await page.getByRole('link',{name:'Тестовый ПК',exact:true}).count()===0){
      await page.locator('[data-device-list] tbody tr').first().waitFor();
      const count=await page.locator('[data-device-list] tbody tr').count();await page.locator('[data-more-devices]').click();
      await page.waitForFunction(n=>document.querySelectorAll('[data-device-list] tbody tr').length>n,count);
    }
    await page.getByRole('link',{name:'Тестовый ПК',exact:true}).click();
    await page.getByRole('searchbox').fill('Тестовый');await page.getByRole('button',{name:'Найти сотрудника',exact:true}).click();
    await page.getByRole('radio').first().check();
    await page.getByLabel('Объект компьютера AD').selectOption({index:1});
    await page.getByRole('button',{name:'Подготовить привязку',exact:true}).click();
    await page.locator('[data-link-confirm]').waitFor({state:'visible'});
    await page.getByLabel('Основание сравнения').fill('Сравнены синтетические GUID и MAC');
    await page.getByRole('button',{name:'Подтвердить привязку',exact:true}).click();
    await page.locator('[data-device-links]').filter({hasText:'Привязка подтверждена'}).waitFor();
    check((await counts()).manual_owner==='Владелец карточки вручную','Directory link overwrote inventory owner');
    await page.screenshot({path:output+'/workstations-desktop-link.png',fullPage:false});
    await page.getByLabel('Причина завершения привязки').fill('Синтетическая проверка истории');
    await page.getByRole('button',{name:'Завершить привязку',exact:true}).click();
    await page.locator('[data-device-links]').filter({hasText:'Привязка завершена'}).waitFor();
    await page.goto(base+'/workstations/reconcile');
    await page.getByRole('button',{name:'Сверить сейчас',exact:true}).click();
    await page.locator('[data-operation]').filter({hasText:'Операция завершена'}).waitFor();
    await page.goto(base+'/workstations/sources');
    await page.locator('[data-sources] tbody tr').nth(3).waitFor();
    await page.getByLabel('Задание',{exact:true}).fill('job-20261015T000000Z-12345678');
    await page.getByRole('button',{name:'Показать журнал',exact:true}).click();
    await page.waitForFunction(()=>document.querySelectorAll('[data-journal] li').length===100);
    check((await page.locator('[data-journal-evidence]').textContent()).includes('прочитана полностью'),'Journal completeness evidence missing');
    await page.getByRole('button',{name:'Ещё события',exact:true}).click();
    await page.waitForFunction(()=>document.querySelectorAll('[data-journal] li').length===200);
    const exportUrl=await page.locator('[data-journal-export]').getAttribute('href');
    const exported=await page.request.get(base+exportUrl).then(response=>response.json());
    check(exported.status==='ok'&&exported.data.events.length>0,'Journal export failed');
    check(!JSON.stringify(exported).includes('onerror='),'Private directory text leaked into the general journal');
    await page.screenshot({path:output+'/workstations-desktop-sources.png',fullPage:false});
    check(apiFailures.length===0,'Unexpected workstation HTTP error');check(consoleErrors.length===0,'Browser console error');
    return {passed:true,viewports:['1360x900','390x844'],apply_delta:(await counts()).apply_count-before.apply_count,verify_delta:(await counts()).verify_count-before.verify_count,
      published_events:205,event_pages:[0,100,200],journal_rendered:await page.locator('[data-journal] li').count(),
      manual_inventory_owner_preserved:true,console_errors:consoleErrors.length,http_errors:apiFailures.length,job_url:jobUrl};
  } finally {page.removeListener('console',listener);page.removeListener('response',responses);}
};

if(require.main===module){
  const fs=require('node:fs'),path=require('node:path');
  const output=process.argv[2];
  if(!output||!path.isAbsolute(output))throw new Error('Provide an absolute private artifact directory');
  fs.mkdirSync(output,{recursive:true});
  (async()=>{
    const {chromium}=require(process.env.WORKSTATIONS_PLAYWRIGHT_MODULE||'playwright');
    const browser=await chromium.launch({headless:true});
    const context=await browser.newContext();
    const page=await context.newPage();
    try {
      const result=await module.exports(page,output);
      fs.writeFileSync(path.join(output,'journey-result.json'),JSON.stringify(result,null,2));
      console.log(JSON.stringify(result));
    } catch(error){
      await page.screenshot({path:path.join(output,'journey-failure.png'),fullPage:false});
      fs.writeFileSync(path.join(output,'journey-failure.txt'),String(error.stack));
      console.error(String(error));process.exitCode=1;
    } finally {await browser.close();}
  })().catch(error=>{console.error(String(error));process.exitCode=1;});
}
