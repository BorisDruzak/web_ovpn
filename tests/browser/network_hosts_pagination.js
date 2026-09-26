// Execute against the loopback inventory_fixture_server, authenticated.
async (page) => {
  await page.goto('http://127.0.0.1:8874/network/hosts');
  await page.locator('select[name="status"]').selectOption('all');
  await page.locator('select[name="seen_within"]').selectOption('all');
  await page.getByRole('button', {name:'Фильтр',exact:true}).click();
  const all = [];
  for (let number = 1; number <= 3; number++) {
    await page.waitForLoadState('networkidle');
    const ips = await page.locator('[data-hosts-rows] tr td:first-child').allTextContents();
    if (ips.length !== (number === 3 ? 30 : 100)) throw new Error('Wrong page size');
    all.push(...ips);
    if (number < 3) await page.getByRole('link', {name:'Следующая',exact:true}).click();
  }
  if (all.length !== 230 || new Set(all).size !== 230) throw new Error('Duplicate/missing hosts');
  await page.goBack();
  if (!page.url().includes('page=2')) throw new Error('Back lost page state');
  await page.goForward();
  if (!page.url().includes('page=3')) throw new Error('Forward lost page state');
  await page.getByRole('spinbutton',{name:'Страница',exact:true}).fill('1');
  await page.getByRole('button',{name:'Перейти',exact:true}).click();
  if (!page.url().includes('page=1')) throw new Error('Page jump failed');
  await page.getByRole('combobox',{name:'На странице',exact:true}).selectOption('25');
  await page.getByRole('button',{name:'Фильтр',exact:true}).click();
  if (await page.locator('[data-hosts-rows] tr').count() !== 25) throw new Error('Size selector failed');
  if (page.url().includes('page=3')) throw new Error('Filter did not reset page');
  await page.getByRole('textbox',{name:'Поиск по IP, MAC, имени'}).fill('no-match');
  await page.getByRole('button',{name:'Фильтр',exact:true}).click();
  if (!(await page.locator('[data-hosts-rows]').innerText()).includes('Нет устройств по выбранным фильтрам')) throw new Error('Empty filter state');
  if (!(await page.locator('[data-host-pagination]').innerText()).startsWith('0 устройств')) throw new Error('Empty pagination state');
  return {uniqueHosts:all.length, pages:3, backForward:true, pageJump:true, size:25, emptyFilter:true};
};
