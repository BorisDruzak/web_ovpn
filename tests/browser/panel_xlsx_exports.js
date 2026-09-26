async (page) => {
  const origin='http://127.0.0.1:8874';
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto(origin+'/network/hosts?status=all&seen_within=all');
  if(page.url().includes('/login')) {
    await page.getByRole('textbox',{name:'Логин',exact:true}).fill('synthetic');
    await page.getByRole('textbox',{name:'Пароль',exact:true}).fill('synthetic-browser-only');
    await page.getByRole('button',{name:'Войти',exact:true}).click();
    await page.goto(origin+'/network/hosts?status=all&seen_within=all');
  }
  await page.getByRole('combobox',{name:'Учёт в инвентаризации',exact:true}).selectOption('unlinked');
  await page.getByRole('textbox',{name:'Название представления',exact:true}).fill('Synthetic actual relation filter');
  await page.getByRole('button',{name:'Сохранить фильтры',exact:true}).click();
  await page.getByRole('button',{name:'Применить',exact:true}).click();
  await page.waitForLoadState('networkidle');
  if(!page.url().includes('inventory_link=unlinked')) throw Error('Actual relation filter not retained');
  if(await page.getByRole('combobox',{name:'Учёт в инвентаризации',exact:true}).inputValue()!=='unlinked') throw Error('Actual filter control mismatch');
  const firstIntent=await page.locator('form[action="/network/export"] [name="operation_key"]').inputValue();
  if(!/^[0-9a-f]{32}$/.test(firstIntent)) throw Error('Missing server export intent');
  await page.getByRole('button',{name:'Excel: весь снимок по текущим фильтрам',exact:true}).click();
  await page.waitForURL('**/operations/**');
  const firstOperation=page.url();
  const networkLink=page.getByRole('link',{name:'Скачать файл',exact:true});
  for(let attempt=0;attempt<25&&!await networkLink.count();attempt++) {
    await page.getByRole('link',{name:'Обновить состояние',exact:true}).click();
    try {await networkLink.waitFor({timeout:1000});} catch(_) {}
  }
  await networkLink.waitFor({timeout:25000});
  const networkDownloadPromise=page.waitForEvent('download');
  await networkLink.click();
  const networkDownload=await networkDownloadPromise;
  await networkDownload.saveAs('C:/Temp/web-ovpn-inventory-browser-v17/network-synthetic.xlsx');
  if(await networkDownload.failure()) throw Error('Network download failed');
  for(let attempt=0;attempt<10;attempt++) {
    await page.goBack();
    if(page.url().includes('/network/hosts?')) break;
  }
  const backIntent=await page.locator('form[action="/network/export"] [name="operation_key"]').inputValue();
  if(!/^[0-9a-f]{32}$/.test(backIntent)||backIntent===firstIntent) throw Error('Browser Back reused old export intent');
  await page.getByRole('button',{name:'Excel: весь снимок по текущим фильтрам',exact:true}).click();
  await page.waitForURL('**/operations/**');
  if(page.url()===firstOperation) throw Error('Browser Back reused completed export');
  await page.goto(origin+'/inventory');
  await page.getByRole('button',{name:'Excel: все активные карточки и история связей',exact:true}).click();
  await page.waitForURL('**/operations/**');
  const inventoryLink=page.getByRole('link',{name:'Скачать файл',exact:true});
  for(let attempt=0;attempt<25&&!await inventoryLink.count();attempt++) {
    await page.getByRole('link',{name:'Обновить состояние',exact:true}).click();
    try {await inventoryLink.waitFor({timeout:1000});} catch(_) {}
  }
  await inventoryLink.waitFor({timeout:25000});
  const inventoryDownloadPromise=page.waitForEvent('download');
  await inventoryLink.click();
  const inventoryDownload=await inventoryDownloadPromise;
  await inventoryDownload.saveAs('C:/Temp/web-ovpn-inventory-browser-v17/inventory-synthetic.xlsx');
  if(await inventoryDownload.failure()) throw Error('Inventory download failed');
  if(errors.length) throw Error(errors.join(';'));
  return {actualSavedRelationFilter:true,browserBackNewIntent:true,networkDownload:true,inventoryDownload:true,pageErrors:errors};
};
