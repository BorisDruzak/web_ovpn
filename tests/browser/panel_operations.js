// Run in the T01 loopback fixture after UI login. All commands are synthetic.
async (page) => {
  const root = await page.evaluate(() => window.location.origin);
  let submitted;
  page.on('request', request => {
    if (request.method() === 'POST' && request.url() === root + '/clients/sync') submitted = request.postData();
  });
  await page.locator('nav').getByRole('link', {name:'Клиенты', exact:true}).click();
  await page.getByRole('button', {name:/Синхрониз/}).click();
  await page.locator('[data-operation-id]').waitFor();
  const operationId = await page.locator('[data-operation-id]').getAttribute('data-operation-id');
  if (await page.locator('[data-operation-status]').getAttribute('data-operation-status') !== 'running') throw Error('CLI barrier was not held');
  const independent = await page.request.get(root + '/login');
  if (independent.status() !== 200) throw Error('Independent request blocked');
  const duplicate = await page.request.post(root + '/clients/sync', {
    form: await page.evaluate(body => Object.fromEntries(new URLSearchParams(body)), submitted), maxRedirects:0,
  });
  if (duplicate.headers()['x-operation-id'] !== operationId) throw Error('Retry created another operation');
  await page.reload();
  if (await page.locator('[data-operation-id]').getAttribute('data-operation-id') !== operationId) throw Error('Reload lost operation');
  await page.request.post(root + '/__fixture/release');
  await page.getByRole('link', {name:'Обновить состояние', exact:true}).click();
  await page.locator('[data-operation-status="succeeded"]').waitFor();
  const state = await page.request.get(root + '/__fixture/state').then(response => response.json());
  if (state.calls !== 1) throw Error('Command executed more than once');
  return {operationId, independent:true, retryDeduplicated:true, reload:true, succeeded:true, calls:state.calls};
};
