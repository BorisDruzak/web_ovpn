// Full E3, synthetic loopback fixture only. Endpoint is disabled by fixture startup.
// Callback reads origin from the current fixture page, so ports 8868/8874 are supported.
async page => {
  const origin=await page.evaluate(()=>location.origin);
  if(!/^http:\/\/127\.0\.0\.1:(8868|8874)$/.test(origin)) throw Error('Synthetic fixture required');
  const errors=[], journeys=[], serverFailures=[];
  page.on('response',response=>{if(response.status()>=500) serverFailures.push(response.status()+' '+response.url());});
  page.on('pageerror',error=>errors.push(error.message));
  page.on('dialog',dialog=>dialog.accept());
  const go=path=>page.goto(origin+path);
  async function source(state) {
    const response=await page.request.post(origin+'/_fixture/live-source/'+state);
    if(!response.ok()) throw Error('Fixture control '+state+' HTTP '+response.status());
  }
  async function exportInventory(label) {
    await go('/inventory');
    await page.getByRole('button',{name:'Excel: все активные карточки и история связей',exact:true}).click();
    await page.waitForURL('**/operations/**');
    const file=page.getByRole('link',{name:'Скачать файл',exact:true});
    for(let attempt=0;attempt<30&&!await file.count();attempt++) {
      await page.getByRole('link',{name:'Обновить состояние',exact:true}).click();
      try {await file.waitFor({timeout:1000});} catch(_) {}
    }
    await file.waitFor({timeout:15000});
    const pending=page.waitForEvent('download'); await file.click();
    const download=await pending;
    // Artifact stays in the isolated fixture's ignored output directory.
    await download.saveAs('C:/Users/admin-2/.codex/worktrees/panel-jobs/ui_vpn/output/playwright/e3-v7/'+label+'.xlsx');
    if(await download.failure()) throw Error('Export failed');
    return download.suggestedFilename();
  }
  async function confirm(key,id) {
    await go('/inventory/network-links?network_key='+encodeURIComponent(key)+'&asset_id='+id);
    const form=page.locator('form[action="/inventory/network-links/confirm"]');
    await form.getByRole('textbox',{name:'Основание сравнения'}).fill('Synthetic physical comparison; all duplicates inspected');
    await form.getByRole('checkbox',{name:'Сравнил физическое устройство с этой карточкой'}).check();
    await form.locator('[name="reconsider"]').check();
    await form.getByRole('button',{name:'Подтвердить связь',exact:true}).click();
    await page.waitForLoadState('networkidle');
    if(!(await page.locator('main').innerText()).includes('Подтверждена')) throw Error('Explicit confirmation failed');
  }
  async function openBoth(key,id) {
    await go('/network/assets/'+encodeURIComponent(key));
    await page.getByRole('link',{name:'Сравнить с инвентаризацией',exact:true}).click();
    const link=page.locator('a[href*="/inventory/assets/'+id+'"]').first();
    await link.waitFor(); await link.click();
    await page.waitForURL('**/inventory/assets/'+id+'?**');
    const block=page.locator('[aria-label="Сеть"]');
    if(!(await block.innerText()).includes(key)) throw Error('Card lost network key');
    await block.locator('a[href^="/network/assets/"]').first().click();
    await page.waitForURL('**/network/assets/**');
    return true;
  }
  await go('/inventory');
  if(page.url().includes('/login')) {
    await page.getByRole('textbox',{name:'Логин',exact:true}).fill('synthetic');
    await page.getByRole('textbox',{name:'Пароль',exact:true}).fill('synthetic-browser-only');
    await page.getByRole('button',{name:'Войти',exact:true}).click();
  }
  for(const unavailable of [false,true]) {
    const number=unavailable?124:24, label=unavailable?'unavailable':'available';
    const key=number===24?'mac:02:00:00:00:00:24':'mac:02:00:00:00:01:24';
    const name='Synthetic E3 '+label+' PC';
    await source('available');
    await go('/inventory/locations/new');
    await page.getByRole('textbox',{name:'Название локации',exact:true}).fill('Synthetic E3 '+label+' location');
    await page.getByRole('button',{name:'СОХРАНИТЬ ЛОКАЦИЮ',exact:true}).click();
    const locationPath=page.url().slice(origin.length).split('?')[0];
    // Find the source in the saved network list, then create its full PC card.
    await go('/network/hosts?status=all&seen_within=all&q='+encodeURIComponent('192.0.2.'+number));
    const row=page.locator('[data-hosts-rows] tr').filter({has:page.locator('td:first-child',{hasText:'192.0.2.'+number})}).first();
    await row.getByRole('link',{name:'Сравнить / связать',exact:true}).click();
    await page.locator('form[action="/inventory/assets/new"] [name="location_id"]').selectOption(locationPath.split('/').pop());
    await page.getByRole('button',{name:'Открыть форму создания',exact:true}).click();
    const form=page.locator('[data-inventory-asset-form]');
    await form.locator('[name="custom_name"]').fill(name);
    await form.locator('[name="ram_gb"]').fill('16');
    await form.locator('[name="network_reason"]').fill('Synthetic physical comparison before creation');
    await form.locator('[name="network_confirmation"]').check();
    await form.getByRole('button',{name:'СОХРАНИТЬ',exact:true}).click();
    await page.waitForURL('**/inventory/locations/**');
    await page.getByRole('link',{name:new RegExp('^'+name+' PC$')}).click();
    const id=page.url().slice(origin.length).split('?')[0].split('/').pop();
    await openBoth(key,id);
    // Select that existing card explicitly: end only its first relation, then confirm again.
    await go('/inventory/network-links?network_key='+encodeURIComponent(key)+'&asset_id='+id);
    const ending=page.locator('form[action$="/end"]');
    await ending.getByRole('textbox',{name:'Причина',exact:true}).fill('Synthetic existing-card selection exercise');
    await ending.getByRole('button',{name:'Завершить только связь',exact:true}).click();
    await confirm(key,id); await openBoth(key,id);
    const peripherals=[];
    for(const [type,title] of [['MONITOR','+ МОНИТОР'],['UPS','+ ИБП']]) {
      await go(locationPath);
      const pc=page.locator('article.inventory-pc').filter({has:page.locator('a[href*="/inventory/assets/'+id+'"]')});
      await pc.getByRole('link',{name:'+ ДОБАВИТЬ СВЯЗАННОЕ УСТРОЙСТВО',exact:true}).click();
      await page.getByRole('link',{name:title,exact:true}).click();
      await page.locator('[data-inventory-asset-form] [name="custom_name"]').fill('Synthetic E3 '+label+' '+type);
      await page.locator('[data-inventory-asset-form]').getByRole('button',{name:'СОХРАНИТЬ',exact:true}).click();
      await page.waitForURL('**/inventory/locations/**');
      const child=page.getByRole('link',{name:new RegExp('^Synthetic E3 '+label+' '+type+' ')});
      const href=await child.getAttribute('href'); peripherals.push(href.split('?')[0].split('/').pop());
    }
    if(unavailable) {
      await source('unavailable');
    }
    await go('/inventory/assets/'+id);
    if(unavailable && !(await page.locator('[aria-label="Сеть"]').innerText()).includes('Синхронизация Netctl не удалась')) throw Error('Unavailable source not explicit');
    await page.locator('[data-inventory-asset-form] [name="custom_name"]').fill(name+' edited');
    await page.locator('[data-inventory-asset-form]').getByRole('button',{name:'СОХРАНИТЬ',exact:true}).click();
    const exportName=await exportInventory(label);
    await go('/inventory/assets/'+id);
    const deletion=page.locator('form[action$="/delete"]');
    await page.locator('summary').filter({hasText:/^Удалить устройство$/}).click();
    await deletion.locator('[name="reason"]').fill('Synthetic E3 lifecycle acceptance');
    await deletion.locator('[name="confirmation"]').check();
    await deletion.getByRole('button',{name:'Удалить устройство',exact:true}).click();
    await page.waitForURL('**/inventory/deleted/'+id);
    if((await page.request.get(origin+'/inventory/assets/'+id)).status()!==404) throw Error('Deleted card still ordinary-visible');
    for(const child of peripherals) if(!(await page.request.get(origin+'/inventory/assets/'+child)).ok()) throw Error('Peripheral deleted');
    await go(locationPath);
    for(const child of peripherals) if(!await page.locator('a[href*="/inventory/assets/'+child+'"]').count()) throw Error('Peripheral location/ID lost');
    await go('/network/assets/'+encodeURIComponent(key));
    if(!(await page.locator('main').innerText()).includes('192.0.2.'+number)) throw Error('Source device deleted');
    await go('/inventory/deleted/'+id);
    await page.getByRole('button',{name:'Восстановить карточку',exact:true}).click();
    await page.waitForURL('**/inventory/assets/'+id+'?**');
    if(await page.locator('[name="custom_name"]').inputValue()!==name+' edited') throw Error('Restore lost manual edit or ID');
    if(!(await page.locator('[aria-label="Сеть"]').innerText()).includes('Завершено')) throw Error('Restore auto-reclaimed binding');
    if(unavailable) {
      const unavailableResponse=await go('/inventory/network-links?network_key='+encodeURIComponent(key)+'&asset_id='+id);
      if(unavailableResponse.status()!==200 || !(await page.locator('[role="alert"]').innerText()).includes('Источник Netctl недоступен')) throw Error('Unavailable comparison must render its explicit safe error');
      // Revalidation has no live identity: there must be no enabled confirm action.
      const action=page.locator('form[action="/inventory/network-links/confirm"] button');
      if(await action.count() && await action.isEnabled()) throw Error('Unavailable live source permits confirmation');
      await source('available');
      await go('/inventory/assets/'+id);
      if(!(await page.locator('[aria-label="Сеть"]').innerText()).includes('Сохранённый снимок актуален')) throw Error('Recovery source not available');
    }
    await confirm(key,id); await openBoth(key,id);
    journeys.push({label,assetId:id,peripheralIds:peripherals,sourceKey:key,exportName,
      bothDirections:true,sameIdRestored:true,peripheralsRetained:true,sourceRetained:true,
      unavailableRelinkBlocked:unavailable,explicitRecoveryRelink:true});
  }
  if(errors.length) throw Error(errors.join(';'));
  if(serverFailures.length) throw Error(serverFailures.join(';'));
  return {result:'PASS',endpointDisabled:true,journeys,pageErrors:errors,serverFailures};
}
