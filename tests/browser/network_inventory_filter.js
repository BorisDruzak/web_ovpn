// Authenticated synthetic loopback fixture only; all source calls are stubs.
async (page) => {
  const errors = [];
  page.on('pageerror',error => errors.push(error.message));
  await page.goto('http://127.0.0.1:8874/inventory/network-links?network_key=mac%3A02%3A00%3A00%3A00%3A00%3A24');
  await page.getByRole('textbox',{name:'Поиск существующей карточки'}).fill('001122334455');
  await page.getByRole('button',{name:'Найти',exact:true}).click();
  const confirm = page.locator('form[action="/inventory/network-links/confirm"]');
  const assetId = await confirm.locator('[name="asset_id"]').inputValue();
  await confirm.locator('[name="reason"]').fill('Synthetic whole-snapshot filter comparison');
  await confirm.locator('[name="confirmation"]').check();
  await confirm.getByRole('button',{name:'Подтвердить связь',exact:true}).click();
  const end = page.locator('form[action$="/end"]').first();
  const action = await end.getAttribute('action');
  const csrf = await end.locator('[name="csrf_token"]').inputValue();
  const revision = await end.locator('[name="expected_revision"]').inputValue();
  await page.goto('http://127.0.0.1:8874/network/hosts?status=all&seen_within=all&inventory_link=linked&page=9&limit=25');
  const rows = page.locator('[data-hosts-rows] tr');
  if (await rows.count() !== 1 || !(await rows.innerText()).includes('192.0.2.24')) throw new Error('Whole-selection linked filter failed');
  if (await page.locator('select[name="inventory_link"]').inputValue() !== 'linked') throw new Error('Filter state lost');
  const snapshot = await page.request.get('http://127.0.0.1:8874/api/v1/network/hosts/meta');
  const snapshotId = (await snapshot.json()).data.snapshot.snapshot_id;
  const result = await page.request.post('http://127.0.0.1:8874'+action,{form:{csrf_token:csrf,expected_revision:revision,reason:'Synthetic second editor ended relation'}});
  if (!result.ok()) throw new Error('Synthetic end failed');
  await page.waitForFunction(() => !document.querySelector('[data-hosts-rows]')?.textContent.includes('192.0.2.24'),{timeout:20000});
  const refreshed = await page.request.get('http://127.0.0.1:8874/api/v1/network/hosts?status=all&seen_within=all&inventory_link=linked');
  const data = (await refreshed.json()).data;
  if (data.pagination.total !== 0 || data.snapshot.snapshot_id !== snapshotId) throw new Error('Local relation refresh mixed snapshot');
  if (errors.length) throw new Error(errors.join(';'));
  return {result:'PASS whole-selection filter/URL/clamp/local-relation refresh with unchanged snapshot',assetId,snapshotId,errors};
}
