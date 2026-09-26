// Execute against the authenticated synthetic loopback fixture only.
async (page) => {
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('http://127.0.0.1:8874/network/hosts?status=all&seen_within=all');
  const networkRow = page.locator('[data-hosts-rows] tr').filter({has:page.locator('td:first-child',{hasText:'192.0.2.24'})});
  await networkRow.getByRole('link',{name:'Сравнить / связать',exact:true}).click();
  await page.getByRole('textbox',{name:'Поиск существующей карточки'}).fill('001122334455');
  await page.getByRole('button',{name:'Найти',exact:true}).click();
  const confirm = page.locator('form[action="/inventory/network-links/confirm"]');
  const assetId = await confirm.locator('[name="asset_id"]').inputValue();
  await confirm.getByRole('textbox',{name:'Основание сравнения'}).fill('Synthetic physical comparison');
  await confirm.getByRole('checkbox',{name:'Сравнил физическое устройство с этой карточкой'}).check();
  await confirm.getByRole('button',{name:'Подтвердить связь',exact:true}).click();
  await page.waitForLoadState('networkidle');
  if (!(await page.locator('body').innerText()).includes('Подтверждена')) throw new Error('Confirmation missing');
  await page.goto(`http://127.0.0.1:8874/inventory/assets/${assetId}`);
  const block = page.locator('[aria-label="Сеть"]');
  if (!(await block.innerText()).includes('192.0.2.24')) throw new Error('Inventory lost observation');
  await block.getByRole('link',{name:'Сравнение и управление связью',exact:true}).click();
  const ending = page.locator('form[action$="/end"]');
  await ending.getByRole('textbox',{name:'Причина',exact:true}).fill('Synthetic explicit detach');
  await ending.getByRole('button',{name:'Завершить только связь',exact:true}).click();
  if (!(await page.locator('body').innerText()).includes('Завершена')) throw new Error('End missing');
  await page.goto(`http://127.0.0.1:8874/inventory/assets/${assetId}`);
  if (!(await page.locator('[aria-label="Сеть"]').innerText()).includes('Завершено')) throw new Error('Ended history lost');
  if (errors.length) throw new Error(errors.join(';'));
  return {result:'PASS normalized MAC search/both registry transitions/confirm/end/history',assetId,errors};
}
