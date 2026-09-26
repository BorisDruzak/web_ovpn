/* Only presentation settings belong in this store. No query text or card values. */
(() => {
  const enums = {
    category: ['all','local_device','vpn_client','router','site_device','network_infra','telephony','mgmt','wan','vipnet_transit','unknown','noise'],
    status: ['','current','all','online','seen','offline','connected','stale'],
    seen_within: ['1h','24h','7d','30d','all'], has_hostname: ['','yes','no'], has_mac: ['','yes','no'],
    limit: ['25','50','100','250'], inventory_link: ['all','linked','unlinked','candidates','conflicts'],
  };
  const sanitizeFilters = (input) => {
    const result = {};
    if (!input || typeof input !== 'object' || Array.isArray(input)) return result;
    for (const [key, allowed] of Object.entries(enums)) {
      if (typeof input[key] === 'string' && allowed.includes(input[key])) result[key] = input[key];
    }
    for (const key of ['source','network']) {
      const value = input[key];
      if (typeof value === 'string' && value.length <= 128 && !/[\x00-\x1f\x7f]/.test(value)) result[key] = value;
    }
    return result;
  };
  const sanitizeState = (input) => ({
    mode: input?.mode === 'diagnostic' ? 'diagnostic' : 'operational',
    views: Array.isArray(input?.views) ? input.views.slice(0,10).filter(view => view && typeof view.name === 'string' && view.name.trim() && view.name.length <= 60)
      .map(view => ({name: view.name.trim(), filters: sanitizeFilters(view.filters), mode: view.mode === 'diagnostic' ? 'diagnostic' : 'operational'})) : [],
  });
  if (typeof module !== 'undefined' && module.exports) module.exports = {sanitizeFilters, sanitizeState};
  if (typeof document === 'undefined') return;
  const controls = document.querySelector('[data-host-views]');
  const table = document.querySelector('[data-network-hosts]');
  const form = document.querySelector('[data-host-filters]');
  if (!controls || !table || !form) return;
  const key = `panel.host-views.v1.${controls.dataset.preferenceUser}`;
  const feedback = controls.querySelector('[data-view-feedback]');
  const select = controls.querySelector('[data-saved-views]');
  const name = controls.querySelector('[data-view-name]');
  let state;
  try { state = sanitizeState(JSON.parse(localStorage.getItem(key) || '{}')); }
  catch (_) { state = sanitizeState({}); feedback.textContent = 'Настройки браузера недоступны или повреждены. Таблица доступна без сохранения.'; }
  const persist = () => {
    try { localStorage.setItem(key,JSON.stringify(state)); return true; }
    catch (_) { feedback.textContent = 'Браузер не разрешает сохранение настроек. Текущий режим работает до перезагрузки.'; return false; }
  };
  const setMode = mode => {
    table.dataset.tableMode = mode;
    controls.querySelectorAll('[data-host-mode]').forEach(button => button.setAttribute('aria-pressed',String(button.dataset.hostMode === mode)));
    state.mode = mode;
  };
  const renderViews = () => {
    select.replaceChildren(new Option('Выберите представление',''));
    state.views.forEach((view,index) => select.add(new Option(view.name,String(index))));
    controls.querySelector('[data-view-apply]').disabled = !state.views.length;
    controls.querySelector('[data-view-delete]').disabled = !state.views.length;
  };
  setMode(state.mode);
  renderViews();
  controls.querySelectorAll('[data-host-mode]').forEach(button => button.addEventListener('click',() => {setMode(button.dataset.hostMode); if (persist()) feedback.textContent='Режим таблицы сохранён.';}));
  controls.querySelector('[data-view-save]').addEventListener('click',() => {
    const label = name.value.trim();
    if (!label) {feedback.textContent='Введите название представления.'; name.focus(); return;}
    const filters = sanitizeFilters(Object.fromEntries(new FormData(form)));
    const existing = state.views.findIndex(view => view.name === label);
    if (existing < 0 && state.views.length >= 10) {feedback.textContent='Можно сохранить до 10 представлений. Удалите ненужное.'; return;}
    const view = {name:label,filters,mode:state.mode};
    if (existing < 0) state.views.push(view); else state.views[existing] = view;
    renderViews();
    select.value=String(existing < 0 ? state.views.length-1 : existing);
    if (persist()) feedback.textContent='Представление сохранено. Поисковый текст не сохранён.';
  });
  controls.querySelector('[data-view-delete]').addEventListener('click',() => {
    if (!select.value) {feedback.textContent='Выберите представление.'; select.focus(); return;}
    state.views.splice(Number(select.value),1); renderViews();
    if (persist()) feedback.textContent='Представление удалено.';
  });
  controls.querySelector('[data-view-apply]').addEventListener('click',() => {
    if (!select.value) {feedback.textContent='Выберите представление.'; select.focus(); return;}
    const view=state.views[Number(select.value)];
    const filters=sanitizeFilters(view.filters);
    for (const field of ['source','network']) {
      const control=form.elements.namedItem(field);
      if (control && !Array.from(control.options).some(option => option.value === filters[field])) filters[field]='all';
    }
    // Reserved T13 values are applied only once the supported filter control exists.
    if (!form.elements.namedItem('inventory_link')) delete filters.inventory_link;
    setMode(view.mode); persist();
    const params=new URLSearchParams(filters); params.set('page','1');
    window.location.assign(`/network/hosts?${params}`);
  });
})();
